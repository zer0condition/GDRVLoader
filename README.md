# gdrv-loader-updated


updated https://github.com/fengjixuchui/gdrv-loader for newer windows version/s (upto latest windows 11 version\s).<br />
added more portability by adding byte loading for the vulnerable driver.<br />

## usage
open command prompt as admin

Load driver:
gdrvloader.exe [targetdrivername].sys

Unload driver:
gdrvloader.exe [loadedtargetdrivername].sys -unload
