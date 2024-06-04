## Pretrain Corpus Generation
The codes are in data_generation/pretrain_data_gen.py
### pretrain_dataset_generation (from pcap to burst)
```
pretrain_dataset_generation(pcap_path,pcap_output_path,output_split_path,select_packet_len=64,
                             corpora_path=multi_corpora_path, start_index=28, enhance_factor = 1, is_multi=True)
```
pretrain_dataset_generation includes the following steps:
1. convert pcapng to pcap
2. split pcap by flow
3. generate burst dataset

In the burst dataset, each line is a burst part. || means that the current stream is new, and an empty line is used to split two neighboring bursts in one stream. An example of burst dataset is:
```
||4500003c529740004006a3c50a080006035a36f8e82901bbfed134790000
0000a002ffff7fd400000204054e0402080a001366ee0000000001030308

45000034529840004006a3cc0a080006035a36f8e82901bbfed1347a8829471f80100157f46300000101080a001366f90aa8de74450000fe5299
40004006a3010a080006035a36f8e82901bbfed1347a8829471f80180157990f00000101080a001366f90aa8de7416030100c5010000c1030308

...

||...
```
If there are multiple datasets, `merge_txts()`


### from burst dataset to bigram type dataset
```
corpora_to_bigram(corpora_path,corpora_bigram_path)
```
An example of bigram type is:
```
||4500 0000 003c 3cce ced4 d440 4000 0040 4006 0649 49f4 f40a 0a2a 2a00 00d3 d317 1742 42ff ffb4 b4bf bfbd bd00 0050 5067 671d 1d9b 9b03 0300 0000 
0000 00a0 a002 02ff ffff ff0e 0e08 0800 0000 0002 0204 0405 05b4 b404 0402 0208 080a 0a00 0000 0055 55d7 d700 0000 0000 0000 0001 0103 0303 0306 

4500 0000 003c 3c00 0000 0040 4000 0033 3306 0625 25c9 c917 1742 42ff ffb4 b40a 0a2a 2a00 00d3 d300 0050 50bf bfbd bdd5 d527 2794 944b 4b67 671d 
9b04 04a0 a012 1271 7120 200d 0db9 b900 0000 0002 0204 0405 05b4 b404 0402 0208 080a 0a1a 1aad ad0a 0afe fe00 0000 0055 55d7 d701 0103 0303 0305 

...

||...
```
### Generate vocab
```
build_BPE(corpora_path)
build_vocab(vocab_path)
```

## Model Pretrain
Pretrain Input Generation
```
python3 pre-training/preprocess.py --corpus_path corpus.txt \
                          --vocab_path models/encryptd_vocab.txt --seq_length 512 \
                          --dataset_path dataset.pt --processes_num 80 --target bertflow
```
Model Pretrain
```
 CUDA_VISIBLE_DEVICES=2,3,4 python3 pre-training/pretrain.py --dataset_path dataset.pt \
                     --vocab_path models/encryptd_vocab.txt \
                     --output_model_path model.bin \
                     --world_size 3 --gpu_ranks 0 1 2 --master_ip tcp://localhost:12345 \
                     --total_steps 90000 --save_checkpoint_steps 10000 --batch_size 64 \
                     --embedding word_pos_seg --encoder transformer --mask fully_visible --target bertflow
```
## Finetuning Data Generation
The codes are in data_generation/finetuning_data_gen.py

### Split Pcap
In the pcap_path, each pacp is one class. 
```
convert_splitcap(pcapng_path, pcap_path, pcap_split_path)
```
In the pcap_path, each dir is one class. In each dir, each pcap includes multiple flows. 
```
convert_splitcap(pcapng_path, pcap_path, pcap_split_path,is_pcap_label=True)
```
Finally, in the pcap_split_path, each dir is one class. In each dir, each pcap is one flow. 

### Generate Data
From pcap to dataset.json, the generated dataset.json is a dict, the key is the class, the value is the list of flows grouped by features.
```
generation_multiP(pcap_split_path+"splitcap" + "/", samples * _category,
         dataset_save_path=dataset_save_path,start_index=28)

```

From dataset.json to train_dataset.tsv,valid_dataset.tsv,test_dataset.tsv
```
dataset_extract(dataset_save_path,
                     pcap_path,
                     features=['datagram',"length","time","direction","message_type"],dataset_level="flow")
```
### Data Augmentation
```
enhance_based_tsv(dataset_save_path+"dataset/","train_dataset.tsv","train_enhance5",enhance_factor=5)
```
## Model Finetuning

```
CUDA_VISIBLE_DEVICES=2 python3 fine-tuning/run_classifier.py --vocab_path models/encryptd_vocab.txt \
                                   --train_path train_dataset.tsv \
                                   --dev_path valid_dataset.tsv \
                                   --test_path test_dataset.tsv \
                                   --pretrained_model_path pretrain_model.bin \
                                   --output_model_path models/finetuned_model.bin\
                                   --epochs_num 4 --earlystop 4 --batch_size 128 --embedding word_pos_seg \
                                   --encoder transformer --mask fully_visible \
                                   --seq_length 320 --learning_rate 6e-5
```
Note: this code is based on [ET_BERT](https://github.com/linwhitehat/ET-BERT) and [UER-py](https://github.com/dbiir/UER-py). Many thanks to the authors.
