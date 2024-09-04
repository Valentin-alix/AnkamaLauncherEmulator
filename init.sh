#!/bin/bash

set -e

poetry run poetry install

# thrift --gen py resources/zaap.thrift && mv gen-py src/gen_zaap