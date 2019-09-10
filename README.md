# CURRYFINGER
`CURRYFINGER` measures a vanilla request for a particular URL against requests directed to specific IP addresses with forced TLS SNI and HTTP Host headers. The tool takes a string edit distance, and emits matches according to a rough similarity metric threshold.

Use it to find the real origin server behind popular CDNs.

Kudos to [christophetd/CloudFlair](https://github.com/christophetd/CloudFlair) for the inspiration.

Check out the corresponding [post](https://dualuse.io/blog/curryfinger/) for details and example usage.

# REQUIREMENTS

```sh
go get -u github.com/corpix/uarand
go get -u github.com/texttheater/golang-levenshtein/levenshtein
```

# BUILDING

```sh
go build
```

# COMPLAINTS

Yes.

# LICENSE

MIT.