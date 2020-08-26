import angr
import claripy
proj = angr.Project('a.out')
#sizes are in bits
bits_size = 20 * 8
stdin = claripy.BVS('stdin', bits_size)

init_state = proj.factory.entry_state(stdin = stdin)

for b in stdin.chop(8):
	# make constraint - every byte != null
	# you can make more constraints - like make sure its printable. but we don't need it here...
	init_state.add_constraints(b >= ' ')
	init_state.add_constraints(b <= '~')

# define simulation
simgr = proj.factory.simgr(init_state)
# run the simulation
simgr.explore()
# check results in final states
for end in simgr.deadended:
	if b"SUCCESS" in end.posix.dumps(1): # check there is success in stdout
		print(end.posix.dumps(0)) # get stdin

