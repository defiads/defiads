# P2P protocol
Messages and associated workflows of the biadne network.

## Encoding
P2P messages are encoded as defined in CBOR, seee RFC 

## Envelope
All message types are members of the same enumeration.

## Connect
At connect the connecting nodes sends:
- highest block hash known to the peer on the Bitcoin network
- min sketch of the ads known to this peer

The accepting node may reply. If it replies it should send:
- highest block hash known to the peer on the Bitcoin network
- min sketch of the ads known to this peer

## Sync IDs
Both peers may compute the difference set implied by the 
exchanged min sketches and may ask the other for an IBLT
of their current ids, stating desired difference set size.

The peer receiving the IBLT computes the difference set
and attempts to enumerate it. In case it fails to enumerate,
it should repeat the request with higher difference set size.

## Sync content
A peer may ask the other for substantiation of a list of ids. 

The other peer should reply to substantiation requests with the
text of inserted ads and SPV proof of their funding or
with the block height of spending transaction for deleted ads.


