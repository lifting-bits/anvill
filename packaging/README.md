# anvill packaging scripts

## How to generate packages

1. Configure and build anvill
2. Set the **DESTDIR** variable to a new folder
3. Run the packaging script, passing the **DESTDIR** folder

Example:

```sh
anvill_version=$(git describe --always)

cpack -D ANVILL_DATA_PATH="/path/to/install/directory" \
      -R ${anvill_version} \
      --config "packaging/main.cmake"
```
