#!/bin/sh

set -e

cmd="$1"

branch=$(git branch --show-current)

if [ "$branch" != "master" ]; then
	echo "$(basename $0): must be run on master branch"
	exit 2
fi

cur=$(git describe --abbrev=0)
cur=${cur#v}

major=$(echo $cur | cut -d. -f 1)
minor=$(echo $cur | cut -d. -f 2)
patch=$(echo $cur | cut -d. -f 3)

if [ "$major" -gt "$(echo $cur | cut -d. -f 1)" ]; then
	minor=0
	patch=0
else
	case $cmd in
		major)
			major=$(($major + 1))
			minor=0
			patch=0
			;;
		minor)
			minor=$(($minor + 1))
			patch=0
			;;
		patch)
			patch=$(($patch + 1))
			;;
		*)
			echo "Usage: $(basename $0) <major|minor|patch>"
			exit 2
			;;
	esac
fi

echo "$cur => $major.$minor.$patch"

read -p "Tag it? (y/N) " RESP

if [ "$RESP" = "y" -o "$RESP" = "Y" ]; then
	sed -i "s/^VERSION = [0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$/VERSION = $major.$minor.$patch/" Makefile
	sed -i "s/^VERSION = [0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$/VERSION = $major.$minor.$patch/" GNUmakefile
	git add Makefile GNUmakefile
	git commit -m "$major.$minor.$patch"
	git tag -m "v$major.$minor.$patch" "$major.$minor.$patch"
fi

exit 0
