"""
This script provides an exmaple to wrap UER-py for classification.
"""
import os
import sys
sys.path.append(os.getcwd())
import random
import argparse
import torch
import torch.nn as nn
from uer.layers import *
from uer.encoders import *
from uer.utils.vocab import Vocab
from uer.utils.constants import *
from uer.utils import *
from uer.utils.optimizers import *
from uer.utils.config import load_hyperparam
from uer.utils.seed import set_seed
from uer.model_saver import save_model
from uer.opts import finetune_opts
from uer.targets import MlmTarget
import tqdm
import numpy as np
from sklearn.metrics import f1_score,precision_score,recall_score

class Classifier(nn.Module):
    def __init__(self, args):
        super(Classifier, self).__init__()
        self.embedding = str2embedding[args.embedding](args, len(args.tokenizer.vocab))
        self.encoder = str2encoder[args.encoder](args)
        self.target = MlmTarget(args,len(args.tokenizer.vocab))

    def forward(self, src, tgt, seg, soft_tgt=None):
        """
        Args:
            src: [batch_size x seq_length]
            tgt: [batch_size x seq_length]
            seg: [batch_size x seq_length]
        """
        # Embedding.
        emb = self.embedding(src, seg)
        # Encoder.
        output = self.encoder(emb, seg)
        loss_mlm, output_mlm, tgt_mlm = self.target.mlm2(output, tgt)
        return loss_mlm, output_mlm, tgt_mlm


def load_or_initialize_parameters(args, model):
    if args.pretrained_model_path is not None:
        print("Initialize with pretrained model.")
        model.load_state_dict(torch.load(args.pretrained_model_path, map_location={'cuda:1':'cuda:0', 'cuda:2':'cuda:0', 'cuda:3':'cuda:0'}), strict=False)
    else:
        print("Initialize with normal distribution.")
        for n, p in list(model.named_parameters()):
            if "gamma" not in n and "beta" not in n:
                p.data.normal_(0, 0.02)


def build_optimizer(args, model):
    param_optimizer = list(model.named_parameters())
    no_decay = ['bias', 'gamma', 'beta']
    optimizer_grouped_parameters = [
                {'params': [p for n, p in param_optimizer if not any(nd in n for nd in no_decay)], 'weight_decay_rate': 0.01},
                {'params': [p for n, p in param_optimizer if any(nd in n for nd in no_decay)], 'weight_decay_rate': 0.0}
    ]
    if args.optimizer in ["adamw"]:
        optimizer = str2optimizer[args.optimizer](optimizer_grouped_parameters, lr=args.learning_rate, correct_bias=False)
    else:
        optimizer = str2optimizer[args.optimizer](optimizer_grouped_parameters, lr=args.learning_rate,
                                                  scale_parameter=False, relative_step=False)
    if args.scheduler in ["constant"]:
        scheduler = str2scheduler[args.scheduler](optimizer)
    elif args.scheduler in ["constant_with_warmup"]:
        scheduler = str2scheduler[args.scheduler](optimizer, args.train_steps*args.warmup)
    else:
        scheduler = str2scheduler[args.scheduler](optimizer, args.train_steps*args.warmup, args.train_steps)
    return optimizer, scheduler


def batch_loader(batch_size, src, tgt, seg, soft_tgt=None):
    instances_num = src.size()[0]
    for i in range(instances_num // batch_size):
        src_batch = src[i * batch_size : (i + 1) * batch_size, :]
        tgt_batch = tgt[i * batch_size : (i + 1) * batch_size]
        seg_batch = seg[i * batch_size : (i + 1) * batch_size, :]
        if soft_tgt is not None:
            soft_tgt_batch = soft_tgt[i * batch_size : (i + 1) * batch_size, :]
            yield src_batch, tgt_batch, seg_batch, soft_tgt_batch
        else:
            yield src_batch, tgt_batch, seg_batch, None
    if instances_num > instances_num // batch_size * batch_size:
        src_batch = src[instances_num // batch_size * batch_size :, :]
        tgt_batch = tgt[instances_num // batch_size * batch_size :]
        seg_batch = seg[instances_num // batch_size * batch_size :, :]
        if soft_tgt is not None:
            soft_tgt_batch = soft_tgt[instances_num // batch_size * batch_size :, :]
            yield src_batch, tgt_batch, seg_batch, soft_tgt_batch
        else:
            yield src_batch, tgt_batch, seg_batch, None


def read_dataset(args, path): #read data with SEP
    dataset, columns = [], {}
    with open(path, mode="r", encoding="utf-8") as f:
        for line_id, line in enumerate(f):
            if line_id == 0:
                for i, column_name in enumerate(line.strip().split("\t")):
                    columns[column_name] = i
                continue
            line = line[:-1].split("\t")
            
            if "text_b" in columns:
                print("error, only one sentence")
            
            text_a = line[columns["text_a"]]
            text_list = text_a.split("[SEP]")[1:]
            if text_list[0].split(" ")[1:-1][9][:2]!="06": #only handle TCP
                continue
            field_cover = {"IPID":[3,4,5], "srcip":[11,12,13,14,15], "dstip":[15,16,17,18,19],"srcport":[19,20,21],"dstport":[21,22,23],
                           "seq":[23,24,25,26,27],"ack":[27,28,29,30,31],"hdrlen":[31,32],"tcpflags":[32,33]}
            mask_fields = ["IPID","srcip","dstip","srcport","dstport","seq","ack","hdrlen","tcpflags"]
            dir_fields = ["srcip","dstip","srcport","dstport"]
            mask_index = []
            for key in mask_fields:
                mask_index.extend(field_cover[key])
            for key in random.sample(dir_fields,1):
                for j in field_cover[key]: 
                    mask_index.remove(j)
            datagramss = []
            mask_index_in_datagramss = []
            for i in range(len(text_list)):
                pac = text_list[i]
                datagrams = pac.split(" ")[1:-1]
                for j in range(len(datagrams)):
                    if i == len(text_list)-1:
                        if j in mask_index:
                            mask_index_in_datagramss.append(len(datagramss))
                    datagramss.append(datagrams[j])
            # print(datagramss)
            # print(mask_index_in_datagramss)
            # for i in mask_index_in_datagramss:
            #     print(datagramss[i])
            newtext_a = ''
            for i in range(len(datagramss)):
                if newtext_a!='':
                    newtext_a += ' '
                newtext_a += datagramss[i]
            text_a_tokens = args.tokenizer.tokenize(newtext_a)

            mask_index_in_tokens = []
            word_ind = 0
            token_ind = 0
            while word_ind < len(datagramss):
                # if datagramss[word_ind] == text_a_tokens[token_ind]:
                #     word_ind += 1
                #     token_ind += 1
                # else:
                temp = text_a_tokens[token_ind].replace('#','')
                if word_ind in mask_index_in_datagramss:
                    mask_index_in_tokens.append(token_ind)
                while datagramss[word_ind] != temp:
                    token_ind += 1
                    temp += text_a_tokens[token_ind].replace('#','')
                    if word_ind in mask_index_in_datagramss:
                        mask_index_in_tokens.append(token_ind)
                word_ind += 1
                token_ind += 1

            # for i in mask_index_in_tokens:
            #     print(text_a_tokens[i])
            src = args.tokenizer.convert_tokens_to_ids([CLS_TOKEN] + text_a_tokens)
            #print(src)
            tgt = [0] * len(src)
            for i in mask_index_in_tokens:
                tgt[i+1] = src[i+1] # consider CLS
                src[i+1] = args.tokenizer.vocab.get(MASK_TOKEN)
            seg = [1] * len(src)
            #print(src)
            #print(tgt)

            if len(src) > args.seq_length:
                src = src[: args.seq_length]
                seg = seg[: args.seq_length]
                tgt = tgt[: args.seq_length] 
            while len(src) < args.seq_length:
                src.append(0)
                seg.append(0)
                tgt.append(0)

            dataset.append((src, tgt, seg))

    return dataset


def train_model(args, model, optimizer, scheduler, src_batch, tgt_batch, seg_batch, soft_tgt_batch=None):
    model.zero_grad()

    src_batch = src_batch.to(args.device)
    tgt_batch = tgt_batch.to(args.device)
    seg_batch = seg_batch.to(args.device)
    if soft_tgt_batch is not None:
        soft_tgt_batch = soft_tgt_batch.to(args.device)

    loss,_,_ = model(src_batch, tgt_batch, seg_batch, soft_tgt_batch)
    if torch.cuda.device_count() > 1:
        loss = torch.mean(loss)

    if args.fp16:
        with args.amp.scale_loss(loss, optimizer) as scaled_loss:
            scaled_loss.backward()
    else:
        loss.backward()

    optimizer.step()
    scheduler.step()

    return loss


def evaluate(args, dataset, print_confusion_matrix=False):
    src = torch.LongTensor([sample[0] for sample in dataset])
    tgt = torch.LongTensor([sample[1] for sample in dataset])
    seg = torch.LongTensor([sample[2] for sample in dataset])

    batch_size = args.batch_size

    correct = 0
    # Confusion matrix.
    if print_confusion_matrix:
        confusion = torch.zeros(args.labels_num, args.labels_num, dtype=torch.long)
    y_true, y_pred = [], []
    args.model.eval()

    for i, (src_batch, tgt_batch, seg_batch, _) in enumerate(batch_loader(batch_size, src, tgt, seg)):
        src_batch = src_batch.to(args.device)
        tgt_batch = tgt_batch.to(args.device)
        seg_batch = seg_batch.to(args.device)
        with torch.no_grad():
            _, output_mlm, tgt_mlm = args.model(src_batch, tgt_batch, seg_batch)
        pred = output_mlm.argmax(dim=-1)
        gold = tgt_mlm
        # for j in range(pred.size()[0]):
        #     if print_confusion_matrix:
        #         confusion[pred[j], gold[j]] += 1
        y_true.extend(gold.cpu())
        y_pred.extend(pred.cpu())
        correct += torch.sum(pred == gold).item()
    

    if print_confusion_matrix:
        print("Confusion matrix:")
        print(confusion)
        cf_array = confusion.numpy()
        # with open("./results/confusion_matrix",'w') as f:
        #     for cf_a in cf_array:
        #         f.write(str(cf_a)+'\n')
        print("Report precision, recall, and f1:")
        eps = 1e-9
        for i in range(confusion.size()[0]):
            p = confusion[i, i].item() / (confusion[i, :].sum().item() + eps)
            r = confusion[i, i].item() / (confusion[:, i].sum().item() + eps)
            if (p + r) == 0:
                f1 = 0
            else:
                f1 = 2 * p * r / (p + r)
            print("Label {}: {:.3f}, {:.3f}, {:.3f}".format(i, p, r, f1))
        

    print("Acc. (Correct/Total): {:.4f} ({}/{}) ".format(correct / len(y_true), correct, len(y_true)))
    # print("Macro precision: {:.4f}, Micro precision: {:.4f}, Weighted precision: {:.4f}".format(
    #     precision_score(y_true,y_pred,average='macro'), precision_score(y_true,y_pred,average='micro'), precision_score(y_true,y_pred,average='weighted')))
    # print("Macro recall: {:.4f}, Micro recall: {:.4f}, Weighted recall: {:.4f}".format(
    #     recall_score(y_true,y_pred,average='macro'), recall_score(y_true,y_pred,average='micro'), recall_score(y_true,y_pred,average='weighted')))
    # print("Macro f1: {:.4f}, Micro f1: {:.4f}, Weighted f1: {:.4f}".format(
    #     f1_score(y_true,y_pred,average='macro'), f1_score(y_true,y_pred,average='micro'), f1_score(y_true,y_pred,average='weighted')))

    return correct / len(y_true)


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    finetune_opts(parser)

    parser.add_argument("--pooling", choices=["mean", "max", "first", "last"], default="first",
                        help="Pooling type.")

    parser.add_argument("--tokenizer", choices=["bert", "char", "space"], default="bert",
                        help="Specify the tokenizer."
                             "Original Google BERT uses bert tokenizer on Chinese corpus."
                             "Char tokenizer segments sentences into characters."
                             "Space tokenizer segments sentences into words according to space."
                             )

    parser.add_argument("--soft_targets", action='store_true',
                        help="Train model with logits.")
    parser.add_argument("--soft_alpha", type=float, default=0.5,
                        help="Weight of the soft targets loss.")
    
    #MOE Model Options
    parser.add_argument("--is_moe", action="store_true", help="adopt moe layer.")
    parser.add_argument("--vocab_size", type=int, required=False, help="Number of vocab.")
    parser.add_argument("--moebert_expert_dim", type=int, required=False, default=3072, help="Dim of expert,default is ffn.")
    parser.add_argument("--moebert_expert_num", type=int, required=False, help="Number of expert.")
    parser.add_argument("--moebert_route_method", choices=["gate-token", "gate-sentence", "hash-random", "hash-balance","proto"], default="hash-random",
                        help="moebert route method.")
    parser.add_argument("--moebert_route_hash_list", default=None, type=str, help="Path of moebert hash list file.")
    parser.add_argument("--moebert_load_balance", type=float, default=0.0, help="gate loss weight.")
    
    args = parser.parse_args()

    # Load the hyperparameters from the config file.
    args = load_hyperparam(args)

    set_seed(args.seed)


    # Build tokenizer.
    args.tokenizer = str2tokenizer[args.tokenizer](args)

    # text_a = "4500 0002 029d 9d5d 5df7 f740 4000 007f 7f06 06fd fd31 3196 96f2 f2a9 a964 6475 7512 12e8 e8c8 c812 123d 3d01 01bb bbb6 b629 2932 32e1 e112 1204 0411 117e 7e50 5018 1802 0200 0091 914d 4d00 0000 0014 1403 0303 0300 0001 0101 0116 1603 0303 0302 026a 6a01 0100 0002 0266 6603 0303 0339 3957 5790 90d6 d6e5 e541 418c 8cf4 4504 0405 05dc dcd0 d062 6200 0000 002b 2b06 061b 1b84 8475 7512 12e8 e8c8 c896 96f2 f2a9 a964 6401 01bb bb12 123d 3d12 1204 0411 117e 7eb6 b629 2935 3556 5650 5010 1000 0085 8563 6398 9800 0000 0016 1603 0303 0300 009b 9b02 0200 0000 0097 9703 0303 03ac ac5b 5b8b 8bfd fd50 50fb fb44 449a 9ad8 d878 78ba bab3 b37d 7dc5 4504 0405 05dc dcd0 d063 6300 0000 002b 2b06 061b 1b83 8375 7512 12e8 e8c8 c896 96f2 f2a9 a964 6401 01bb bb12 123d 3d12 1204 0417 1732 32b6 b629 2935 3556 5650 5010 1000 0085 85e6 e6c8 c800 0000 00f9 f953 53a4 a4cb cb74 74a3 a33a 3aee ee66 661f 1f15 15ac ac0a 0a90 90af af65 6548 4819 1916 16cf cff3 f369 69aa aa7c 7ced 4504 0404 04c0 c0d0 d064 6400 0000 002b 2b06 061c 1c9e 9e75 7512 12e8 e8c8 c896 96f2 f2a9 a964 6401 01bb bb12 123d 3d12 1204 041c 1ce6 e6b6 b629 2935 3556 5650 5018 1800 0085 8548 488a 8a00 0000 00b9 b995 954b 4b2b 2b9d 9d6b 6b80 8098 9890 90f8 f8f2 f21c 1caa aa70 708f 8f12 128d 8dbc bc34 3405 055d 5d26 268a 8afa faaa"
    # print(text_a.split(" "))
    # b = args.tokenizer.tokenize(text_a)
    # print(len(b))
    # print(b)

    # exit()

    # Build classification model.
    model = Classifier(args)

    # Load or initialize parameters.
    load_or_initialize_parameters(args, model)

    args.device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    model = model.to(args.device)

    if args.train_path is None:
        print("No train data, only evaluate..")
        result = evaluate(args, read_dataset(args, args.dev_path))
        return
    
    # Training phase.
    trainset = read_dataset(args, args.train_path)
    random.shuffle(trainset)
    instances_num = len(trainset)
    batch_size = args.batch_size
    
    src = torch.LongTensor([example[0] for example in trainset])
    tgt = torch.LongTensor([example[1] for example in trainset])
    seg = torch.LongTensor([example[2] for example in trainset])
    if args.soft_targets:
        soft_tgt = torch.FloatTensor([example[3] for example in trainset])
    else:
        soft_tgt = None

    args.train_steps = int(instances_num * args.epochs_num / batch_size) + 1

    print("Batch size: ", batch_size)
    print("The number of training instances:", instances_num)

    optimizer, scheduler = build_optimizer(args, model)

    if args.fp16:
        try:
            from apex import amp
        except ImportError:
            raise ImportError("Please install apex from https://www.github.com/nvidia/apex to use fp16 training.")
        model, optimizer = amp.initialize(model, optimizer, opt_level=args.fp16_opt_level)
        args.amp = amp

    if torch.cuda.device_count() > 1:
        print("{} GPUs are available. Let's use them.".format(torch.cuda.device_count()))
        model = torch.nn.DataParallel(model)
    args.model = model

    total_loss, result, best_result = 0.0, 0.0, 0.0

    print("Start training.")

    for epoch in tqdm.tqdm(range(1, args.epochs_num + 1)):
        model.train()
        for i, (src_batch, tgt_batch, seg_batch, soft_tgt_batch) in enumerate(batch_loader(batch_size, src, tgt, seg, soft_tgt)):
            loss = train_model(args, model, optimizer, scheduler, src_batch, tgt_batch, seg_batch, soft_tgt_batch)
            total_loss += loss.item()
            if (i + 1) % args.report_steps == 0:
                print("Epoch id: {}, Training steps: {}, Avg loss: {:.3f}".format(epoch, i + 1, total_loss / args.report_steps))
                total_loss = 0.0

        result = evaluate(args, read_dataset(args, args.dev_path))
        if result > best_result:
            best_result = result
            save_model(model, args.output_model_path)

    # Evaluation phase.
    if args.test_path is not None:
        print("Test set evaluation.")
        if torch.cuda.device_count() > 1:
            model.module.load_state_dict(torch.load(args.output_model_path))
        else:
            model.load_state_dict(torch.load(args.output_model_path))
        evaluate(args, read_dataset(args, args.test_path), False)


if __name__ == "__main__":
    main()
