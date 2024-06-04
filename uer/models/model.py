import torch
import torch.nn as nn


class Model(nn.Module):
    """
    Pretraining models consist of three parts:
        - embedding
        - encoder
        - target
    """
    def __init__(self, args, embedding, encoder, target):
        super(Model, self).__init__()
        self.embedding = embedding
        self.encoder = encoder
        self.target = target
        
        
        if args.target in ['bert','bertflow','mlm'] and args.tie_weights:
            self.target.mlm_linear_2.weight = self.embedding.word_embedding.weight
        elif args.target in ['lm','t5'] and args.tie_weights:
            self.target.output_layer.weight = self.embedding.word_embedding.weight

        if args.target == 't5' and args.share_embedding:
            self.target.embedding.word_embedding.weight = self.embedding.word_embedding.weight
        
        self.is_moe = args.is_moe

    def forward(self, src, tgt, seg, proto=None):
        emb = self.embedding(src, seg)
        if self.is_moe:
            output,gate_loss = self.encoder(emb, seg, src, proto)
            loss_info = self.target(output, tgt) + (gate_loss,)
        else:
            output = self.encoder(emb, seg)
            loss_info = self.target(output, tgt)
        return loss_info
