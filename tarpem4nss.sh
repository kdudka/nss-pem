#!/bin/bash
# Creates the source tar ball for use by nss.spec
# The archive is added to git lookaside cache for nss

tar cvjf nss-pem-$(date +%Y%m%d).tar.bz2 mozilla
