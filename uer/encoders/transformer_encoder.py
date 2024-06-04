import torch
import torch.nn as nn
from uer.layers.transformer import TransformerLayer,TransformerMOELayer
from uer.layers.layer_norm import LayerNorm, T5LayerNorm
from uer.layers.relative_position_embedding import RelativePositionEmbedding
import pickle

class TransformerEncoder(nn.Module):
    """
    BERT encoder exploits 12 or 24 transformer layers to extract features.
    """
    def __init__(self, args):
        super(TransformerEncoder, self).__init__()
        self.mask = args.mask
        self.layers_num = args.layers_num
        self.parameter_sharing = args.parameter_sharing
        self.factorized_embedding_parameterization = args.factorized_embedding_parameterization
        self.layernorm_positioning = args.layernorm_positioning
        self.relative_position_embedding = args.relative_position_embedding
        self.is_moe = args.is_moe
        has_bias = bool(1 - args.remove_transformer_bias)

        if self.factorized_embedding_parameterization:
            self.linear = nn.Linear(args.emb_size, args.hidden_size)
        
        if args.is_moe:
            transformer_layer = TransformerMOELayer
        else:
            transformer_layer = TransformerLayer

        if self.parameter_sharing:
            self.transformer = transformer_layer(args)
        else:
            self.transformer = nn.ModuleList(
                [transformer_layer(args) for _ in range(self.layers_num)]
            )
        if self.layernorm_positioning == "pre":
            if args.layernorm == "t5":
                self.layer_norm = T5LayerNorm(args.hidden_size)
            else:
                self.layer_norm = LayerNorm(args.hidden_size)

        if self.relative_position_embedding:
            self.relative_pos_emb = RelativePositionEmbedding(bidirectional=True, heads_num=args.heads_num,
                                                              num_buckets=args.relative_attention_buckets_num)


    def forward(self, emb, seg, input_ids=None, proto=None):
        """
        Args:
            emb: [batch_size x seq_length x emb_size]
            seg: [batch_size x seq_length]
        Returns:
            hidden: [batch_size x seq_length x hidden_size]
        """
        if self.factorized_embedding_parameterization:
            emb = self.linear(emb)

        batch_size, seq_length, _ = emb.size()
        # Generate mask according to segment indicators.
        # mask: [batch_size x 1 x seq_length x seq_length]
        if self.mask == "fully_visible":
            mask = (seg > 0). \
                unsqueeze(1). \
                repeat(1, seq_length, 1). \
                unsqueeze(1)
            mask = mask.float()
            mask = (1.0 - mask) * -10000.0
        elif self.mask == "causal":
            mask = torch.ones(seq_length, seq_length, device=emb.device)
            mask = torch.tril(mask)
            mask = (1.0 - mask) * -10000
            mask = mask.repeat(batch_size, 1, 1, 1)
        else:
            mask_a = (seg == 1). \
                unsqueeze(1). \
                repeat(1, seq_length, 1). \
                unsqueeze(1).float()

            mask_b = (seg > 0). \
                unsqueeze(1). \
                repeat(1, seq_length, 1). \
                unsqueeze(1).float()

            mask_tril = torch.ones(seq_length, seq_length, device=emb.device)
            mask_tril = torch.tril(mask_tril)
            mask_tril = mask_tril.repeat(batch_size, 1, 1, 1)

            mask = (mask_a + mask_b + mask_tril >= 2).float()
            mask = (1.0 - mask) * -10000.0

        hidden = emb

        if self.relative_position_embedding:
            position_bias = self.relative_pos_emb(hidden, hidden)
        else:
            position_bias = None
        
        probss = []
        gate_loss = 0.0
        for i in range(self.layers_num):
            if self.parameter_sharing:
                if self.is_moe:
                    hidden,banlance_loss = self.transformer(hidden, mask, position_bias=position_bias, expert_input_ids=input_ids, proto=proto)
                    gate_loss+=banlance_loss
                else:
                    hidden,probs = self.transformer(hidden, mask, position_bias=position_bias)
            else:
                if self.is_moe:
                    hidden,banlance_loss = self.transformer[i](hidden, mask, position_bias=position_bias, expert_input_ids=input_ids, proto=proto)
                    gate_loss+=banlance_loss
                else:
                    hidden,probs = self.transformer[i](hidden, mask, position_bias=position_bias)
            probss.append(probs)

        # with open("/mnt/data/zgm/ET-BERT/fine-tuning/attentions/attention.pkl","wb") as f:
        #     pickle.dump(probss,f)

        if self.layernorm_positioning == "pre":
            if self.is_moe:
                return self.layer_norm(hidden),gate_loss
            else:
                return self.layer_norm(hidden)
        else:
            if self.is_moe:
                return hidden,gate_loss
            else:
                return hidden
