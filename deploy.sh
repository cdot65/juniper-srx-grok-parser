#!/usr/bin/env bash

# upgrade current instance
helm upgrade --wait --install logstash --values ./values.yaml ./
