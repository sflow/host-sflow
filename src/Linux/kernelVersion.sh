#!/bin/bash
uname -r | awk -F '\\.' -- '{ print ($1 * 1000000) + ($2 * 1000) + $3;}'
