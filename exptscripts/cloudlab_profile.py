"""An example of constructing a profile with two physical nodes connected by a Link.

Instructions:
Wait for the profile instance to start, and then log in to either host.
"""

import geni.portal as portal
import geni.rspec.pg as rspec

request = portal.context.makeRequestRSpec()

# Create two raw "PC" nodes
nodes = []
for i in range(1):
    n = request.RawPC("node{}".format(i+1))
    # n.hardware_type = 'c220g2'
    n.disk_image = 'urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU18-64-STD'
    nodes.append(n)

# Create a link between them
# link1 = request.Link(members = [node1, node2])

portal.context.printRequestRSpec()
