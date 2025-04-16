#!/bin/bash

pandoc --toc -V geometry:paperwidth=8.5in -V geometry:paperheight=11in -V geometry:margin=1in ethical_hacking.md -o homework.pdf --template eisvogel --listings
