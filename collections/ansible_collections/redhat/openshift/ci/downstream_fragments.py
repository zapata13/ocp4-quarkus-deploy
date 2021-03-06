#!/usr/bin/env python

import json
import yaml
import sys

with open("./rendereddocfragments.txt", 'w') as df_fd:
    with open(sys.argv[2], 'r') as fd:
        json_docs = json.load(fd)

        json_docs[sys.argv[1]]['doc'].pop('collection', '')
        json_docs[sys.argv[1]]['doc'].pop('filename', '')

        df_fd.write("DOCUMENTATION = '''\n")
        df_fd.write(yaml.dump(json_docs[sys.argv[1]]['doc'], default_flow_style=False))
        df_fd.write("'''\n\n")

        df_fd.write("EXAMPLES = '''\n")
        df_fd.write(json_docs[sys.argv[1]]['examples'])
        df_fd.write("'''\n\n")

        df_fd.write("RETURN = '''\n")
        df_fd.write(yaml.dump(json_docs[sys.argv[1]]['return'], default_flow_style=False))
        df_fd.write("'''\n\n")


