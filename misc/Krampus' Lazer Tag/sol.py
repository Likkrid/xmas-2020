#!/usr/bin/env python3
from pwn import *
import re

def laser_beams_bodyguard(a, b, c, d):
	return [
		( (c+a)/2, (d+b)/2 ),
		( (c-a)/2, (d-b)/2 ),
		( (c+a)/2, (d-b)/2 ),
		( (c-a)/2, (d+b)/2 ),

		( (c+a)/2, 1-((d+b)/2) ),
		( (c-a)/2, 1-((d-b)/2) ),
		( (c+a)/2, 1-((d-b)/2) ),
		( (c-a)/2, 1-((d+b)/2) ),

		( 1-((c+a)/2), (d+b)/2 ),
		( 1-((c-a)/2), (d-b)/2 ),
		( 1-((c+a)/2), (d-b)/2 ),
		( 1-((c-a)/2), (d+b)/2 ),

		( 1-((c+a)/2), 1-((d+b)/2) ),
		( 1-((c-a)/2), 1-((d-b)/2) ),
		( 1-((c+a)/2), 1-((d-b)/2) ),
		( 1-((c-a)/2), 1-((d+b)/2) )
	]

self_pattern  = re.compile("Your position: (.*)\n")
krampus_pattern  = re.compile("Krampus' position: (.*)\n")

r = remote("challs.xmas.htsp.ro", 6005)
print(r.recv())
r.sendline()
s = r.recv()
print(f"first: {s}")

while True:
	a, b = [float(i) for i in krampus_pattern.search(s.decode()).group(1).split(",")]
	c, d = [float(i) for i in self_pattern.search(s.decode()).group(1).split(",")]

	if a < c and b < d:
		bodygards_reflections = laser_beams_bodyguard(a, b, c, d)
	elif a > c and b > d:
		bodygards_reflections = laser_beams_bodyguard(c, d, a, b)
	elif a < c and b > d:
		bodygards_reflections = laser_beams_bodyguard(a, d, c, b)
	else:
		bodygards_reflections = laser_beams_bodyguard(c, d, a, b)
	pos = []

	for x_i, y_i in bodygards_reflections:
		pos.append(f"{x_i},{y_i}")
	print(len(pos))
	payload = "\n".join(pos)

	r.sendline(payload)
	print(payload)
	s = r.recv()
	print(s)
	#X-MAS{Wh3n_11F3_5h0Ot5_14Z3r5_a7_y0U_28f901ab}