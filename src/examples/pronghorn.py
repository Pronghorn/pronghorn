#!/usr/bin/env python

from Tkinter import *
from Tix import *
import math

# This class copied from http://effbot.org/zone/tkinter-autoscrollbar.htm
class AutoScrollbar(Scrollbar):
	# a scrollbar that hides itself if it's not needed.  only
	# works if you use the grid geometry manager.
	def set(self, lo, hi):
		if float(lo) <= 0.0 and float(hi) >= 1.0:
			# grid_remove is currently missing from Tkinter!
			self.tk.call("grid", "remove", self)
		else:
			self.grid()
		Scrollbar.set(self, lo, hi)
	def pack(self, **kw):
		raise TclError, "cannot use pack with this widget"
	def place(self, **kw):
		raise TclError, "cannot use place with this widget"

radius = 0
node_angle = 0

def get_node_coordinate(i):
	x = radius * math.sin(node_angle * i)
	y = radius * math.cos(node_angle * i)
	return (x, y)

# INITIAL SETUP
# Some values are provided by pronghorn, others are just config variables

#num_blocks = 100000000000 // 512
num_blocks = 10000

# we want one node per block around a circle, separated by the following distance
separation = 10
node_radius = 2

# This means that the circumference is approx 2 * Pi * r
radius = ((separation * num_blocks) / 2) / math.pi
print "radius is %f" % (radius)

# Angular distance is 2 * Pi / num_blocks
node_angle = (2 * math.pi) / num_blocks
print "node_angle is %f" % (node_angle)

# FINISHED SETUP
# Now we're doing the graphing thing

root = Tk()
root.title("Pronghorn node graph")

vscrollbar = AutoScrollbar(root)
vscrollbar.grid(row=0, column=1, sticky=N+S)
hscrollbar = AutoScrollbar(root, orient=HORIZONTAL)
hscrollbar.grid(row=1, column=0, sticky=E+W)

canvas = Canvas(root, yscrollcommand=vscrollbar.set, xscrollcommand=hscrollbar.set)
canvas.grid(row=0, column=0, sticky=N+S+E+W)

vscrollbar.config(command=canvas.yview)
hscrollbar.config(command=canvas.xview)

# make the canvas expandable
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

for i in range(0, num_blocks):
	(x, y) = get_node_coordinate(i)

#	print "i=%d x=%f, y=%f" % (i, x, y)
	canvas.create_oval(x - node_radius, y - node_radius, x + node_radius, y + node_radius)
#	(x2, y2) = get_node_coordinate((i + (num_blocks//2)) % num_blocks)
#	canvas.create_line(x, y, x2, y2)

canvas.config(scrollregion=canvas.bbox("all"))

root.mainloop()

