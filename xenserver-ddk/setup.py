from xcp.supplementalpack import *
from optparse import OptionParser

parser = OptionParser()
parser.set_defaults(iso=False, tar=False)
parser.add_option('--output', dest="outdir")
parser.add_option('--iso', action="store_true", dest="iso")
parser.add_option('--tar', action="store_true", dest="tar")
parser.add_option('--vendor-code', dest="originator")
parser.add_option('--vendor-name', dest="vendor")
parser.add_option('--label', dest="name")
parser.add_option('--text', dest="description")
parser.add_option('--version', dest="version")
parser.add_option('--build', dest="build")
(options, args) = parser.parse_args()

if None in (options.originator, options.vendor, options.name, 
            options.description, options.version):
    raise SystemExit, "Missing mandatory argument"
if not options.iso and not options.tar:
    raise SystemExit, "One of --tar and --iso required"

xcp = Requires(originator='xcp', name='main', test='eq', 
               product='XCP', version='2.1.0', 
               build='125770c')

output = []
if options.iso:
    output.append('iso')
if options.tar:
    output.append('tar')

setup(originator=options.originator, name=options.name, product='XCP', 
      version=options.version, build=options.build, vendor=options.vendor,
      description=options.description, packages=args, requires=[xcp],
      outdir=options.outdir, output=output)
