#!/bin/sh

if [ -n "$dev"   ]; then exec python -m debugpy --listen 0.0.0.0:5678 openslides_backend; fi
if [ -n "$prod"  ]; then exec python -m openslides_backend; fi