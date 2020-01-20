Economics of Defiads
====================

Defiads uses locked bitcoins to provide consensus on which advertisements
are worth propagating and retaining in the limited amount of memory that
defiads nodes allocate for advertisements.

The locked bitcoins represent an opportunity cost: instead of being locked
in a defiads contract, it could have been used in a Lightning forwarding
node, or a JoinMarket yield generator, or any other money-earning
investment.
By instead locking the money in a defiads contract, the money cannot be used
for such purposes, and the potential earnings that could have been earned
there are instead the fee that is paid in order to prevent spam from
overtaking the defiads network.

The limited amount of advertisement storage exists as a limit on spam as
well as local storage.
If a spammer wants to spend the precious bandwidth of the network to spread
their ads, they need to lock enough funds to beat the lowest-valued ads
that fit in the ad storage limit that most defiads nodes on the network
impose.
This represents an opportunity cost, meaning that spamming the network is
costly.

HODLer as Advertising Agency
============================

An advertiser can outright buy some bitcoins, use it to back a defiads
advertisement, then at the end of the advertisement term, sell the
bitcoins to get back whatever its preferred store-of-value or
unit-of-account.

Alternately, the advertiser can contact a sufficiently large HODLer,
and instead *rent* a fund.
In this case, the advertiser simply arranges to pay the HODLer somehow
in exchange for the HODLer committing to a defiads advertisement.
In this view, the HODLer owns a UTXO that is potentially a blank
advertisement space, which the HODLer can monetize by renting out to
defiads advertisers.

This arrangement is beneficial to both the advertiser and the HODLer.
The advertiser is not exposed to any volatility risk of the bitcoin,
since it is not holding its own money in the fund.
The HODLer gets to stack more sats using the rental fee from the
advertisement.

The HODLer can retain control of the fund by requiring that the defiads
contract contains a pubkey it controls by itself.
The defiads contract currently used at the time of this writing involves a
relative locktime, thus the advertiser knows that if the contract is
published, the HODLer cannot renege and immediately claim the fund for
its own use, for example to rent it again immediately to someone else.

The advertiser and the HODLer can ensure atomicity by having the transaction
that instantiates this fund spend from a UTXO from the advertiser (the
rental payment from the advertiser) and a UTXO from the HODLer (the HEDL
funds of the HODLer).
Successful spending of both inputs leads to a single fund that commits to
the advertisement, locked in the specified term.
Thus, paying the rent and publishing the commitment to the advertisement
is atomic.

The rent on the fund will approach the earnings that the fund would
otherwise earn on other investments.
Thus, the rate of rentals for defiads advertisements will approximate
the expected low-risk rate of return for the Bitcoin economy as a
whole.

Groups of HODLers
-----------------

As defiads use increases, competition for the limited amount of
advertising storage the majority of defiads nodes stores becomes tighter.
Thus, larger and larger funds will need to be used in order to get into
this limited advertising space.

This may eventually require that groups of HODLers provide aggregate funds
to back individual advertisements.
To do so, defiads can switch to Schnorr signatures, and the aggregate can
use n-of-n MuSig as the signing key for the retrieval of the funds.
Then, the HODLers can provide as inputs their individual UTXOs, to generate
an anchor transaction that commits to the advertisement.
Then, prior to signing this transaction, they create a claim transaction
that redistributes the funds back to them (plus their cut of the rental
fee) and sign it using MuSig.
Then they can sign the inputs of the anchor transaction together with the
advertiser.
