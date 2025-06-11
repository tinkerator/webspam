# webspam - handy way to recognize common web requests as spam

## Overview

Webserver traffic can be dominated by SPAM requests. Based on what
we've seen on zappem.net some patterns are more common than
others. This package summarizes them and provides a way to classify
them.

Consistent with some suggestions on the web, we use the 429 status
code when detecting spam.

## License info

The `webspam` package is distributed with the same BSD 3-clause
license as that used by [golang](https://golang.org/LICENSE) itself.

## Reporting bugs and feature requests

The package `webspam` is hoped to be useful. It is maintained on a
best effort basis. If you find a bug or want to suggest a feature
addition, please use the [bug
tracker](https://github.com/tinkerator/webspam/issues).
