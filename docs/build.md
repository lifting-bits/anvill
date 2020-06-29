# how to build

anvill have a dependency related remill specified version. (.remill_commit_id)

a lot of way to build anvill, but easy way is just anvill foder add to remill like mcsema and run build script.

```bash
git clone https://github.com/lifting-bits/anvill

git clone https://github.com/lifting-bits/remill

mv ./anvill ./remill/tools

cd ./remill

git checkout -b temp $(cat ../anvill/.remill_commit_id)

./scripts/build.sh
```