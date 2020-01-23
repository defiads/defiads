A Brief History of Defiads
==========================

Originally, Tyler H proposed a system called [Numerifides][],
where locked funds on the Bitcoin blockchain would be used to
back particular claims to truth, such as associating a
human-readable name with an IP address.
This was originally designed as an alternative to DNS and
Namecoin.

ZmnSCPxj subsequently proposed some refinements to this basic
protocol.
Off-list, he would continue to play with Numerifides-based ideas
as well, eventually creating a plan for a Bitcoin Classified Ads
Network (which was never published).
In particular, the use of DNS (which Numerifides was intended to
replace) to discover other Bitcoin and Lightning nodes also made
ZmnSCPxj consider that such a Bitcoin Classified Ads Network
could be used as a way to discover *economic* partners, such as
service providers (Lightning Watchtowers, Buyers/Sellers of
non-cryptocurrency financial instruments, CoinJoin partners).
Advertisements are basically claims to truth ("we sell the best
products of type X") that happen to have some economic incentive
to propagate and attest.
Finally, Lightning refuses to propagate node announcements unless
that node locks *some* funds into at least one channel, thus this
locking of funds also doubled as a spam-mitigation measure.

More than a year later, Tamas Blummer would propose the use of
[covenant as financial instrument][].
ZmnSCPxj would later respond to this thread, describing the
initial sketch of [BCAN][], as an alternative to the covenant
idea by Tamas Blummer to determine the risk-free rate of
return of the economy.
This proposal also had the advantage of being implementable with
the Bitcoin of that time.

Subsequently, Tamas would directly communicate with ZmnSCPxj
to further refine this initial sketch, and actually plan on
instantiating an implementation.
Eventually, Tamas proposed an alternate name, defiads, and
started this actual implementation of the Numerifides / BCAN
idea, eventually culminating in a [defiads announcement][]
and this repository.

<!-- References -->

[Numerifides]: https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-April/001207.html
[covenant as financial instrument]: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-June/017059.html
[BCAN]: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-July/017083.html
[defiads announcement]: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-September/017299.html
