Discovering and publishing OpenPGP certificates over the network.

This crate provides access to keyservers using the [HKP] protocol,
and searching and publishing [Web Key Directories].

  [HKP]: https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
  [Web Key Directories]: https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service

When the `dane-client` feature is enabled (it is not enabled by
default), it also supports fetching certificates using [DANE].

  [DANE]: https://datatracker.ietf.org/doc/rfc7929/
