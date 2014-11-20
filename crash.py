#!/usr/bin/env python
import sys, json, subprocess, argparse

parser = argparse.ArgumentParser(description='Symbolicate iOS crash report')
parser.add_argument('crashreport', help='crash report file')
parser.add_argument('executable', help='App executable')
parser.add_argument('dsym', help='dSYM file')

args = vars(parser.parse_args())
executable = args['executable']
dsym = args['dsym']

inf = open(args['crashreport'])
#inf = sys.stdin
lines = inf.readlines()
pos = 0

meta = {}
threads = {}

for pos in range(0, len(lines)):
	line = lines[pos]
	if line.startswith('Incident Identifier'):
		meta['incident_identifier'] = line.split(':')[1].strip()
		continue
	if line.startswith('CrashReporter Key'):
		meta['crashreporter_key'] = line.split(':')[1].strip()
		continue
	if line.startswith('Hardware Model'):
		meta['hardware_model'] = line.split(':')[1].strip()
		continue
	if line.startswith('Process'):
		meta['process'] = line.split(':')[1].strip()
		continue
	if line.startswith('Path'): 
		meta['path'] = line.split(':')[1].strip()
		continue
	if line.startswith('Identifier'):
		meta['identifier'] = line.split(':')[1].strip()
		continue
	if line.startswith('Version'):
		meta['version'] = line.split(':')[1].strip()
		continue
	if line.startswith('Code Type'):
		meta['code_type'] = line.split(':')[1].strip()
		continue
	if line.startswith('Parent Process'):
		meta['parent_process'] = line.split(':')[1].strip()
		continue
	if line.startswith('Date/Time'):
		meta['date_time'] = line.split(':')[1].strip()
		continue
	if line.startswith('OS Version'):
		meta['os_version'] = line.split(':')[1].strip()
		continue
	if line.startswith('Report Version'):
		meta['report_version'] = line.split(':')[1].strip()
		continue
	if line.startswith('Exception Type'):
		meta['exception_type'] = line.split(':')[1].strip()
		continue
	if line.startswith('Exception Codes'):
		meta['exception_codes'] = line.split(':')[1].strip()
		continue
	if line.startswith('Crashed Thread'):
		meta['crashed_thread'] = line.split(':')[1].strip()
		continue

	if line.startswith('Thread'):
		break

# Thread State
threads = []
for pos in range(pos, len(lines)):
	line = lines[pos]
	if 'Thread State' in line:
		break
	if line.startswith('Thread'):
		elements = lines[pos].split()
		thread = {}
		thread['number'] = int(elements[1].translate(None, ':'))
		if 'Crashed' in line:
			thread['crashed'] = True
		else:
			thread['crashed'] = False

		stacktrace = []
		for pos in range(pos + 1, len(lines)):
			if lines[pos].startswith('Thread'):
				break
			elements = lines[pos].split()
			if len(elements) >= 6:
				stack = {}
				stack['seq'] = elements[0]
				stack['name'] = elements[1]
				stack['addr'] = elements[2]
				stack['addr1'] = elements[3]
				stack['offset'] = elements[5]
				stacktrace.append(stack)
		thread['stacktrace'] = stacktrace
		threads.append(thread)

states = {}
for pos in range(pos + 1, len(lines)):
	if lines[pos].startswith('Binary Images'):
		break
	elements = lines[pos].split()
	for i in range(0, len(elements), 2):
		regname = elements[i].translate(None, ':')
		value = elements[i + 1]
		states[regname] = value

images = []
for pos in range(pos + 1, len(lines)):
	elements = lines[pos].split()
	image = {}
	image['addr1'] = elements[0]
	image['addr2'] = elements[2]
	image['name'] = elements[3].translate(None, '+')
	image['arch'] = elements[4]
	image['uuid'] = elements[5].translate(None, '<>')
	image['path'] = elements[6]
	images.append(image)

#print json.dumps(crashreport)

arch = meta['code_type']
if arch == 'ARM-64': arch = 'arm64'

cmd = subprocess.Popen('/usr/bin/otool -arch ' + arch + ' -l ' + executable, shell=True, stdout=subprocess.PIPE)
lines = cmd.stdout.readlines()

loads = []
for pos in range(0, len(lines)):
	if lines[pos].startswith('Load command'):
		elements = lines[pos].split()
		index = int(elements[2])
		command = {}
		for pos in range(pos + 1, len(lines)):
			if lines[pos].startswith('Load command'):
				break
			elements = lines[pos].split()
			if len(elements) >= 2:
				command[elements[0]] = elements[1]
		command['index'] = index
		loads.append(command)

#print loads

for load in loads:
	if 'segname' in load and load['segname'] == '__TEXT':
		slide_addr = int(load['vmaddr'], 0)
		break

stack_addr = int(images[0]['addr1'], 0)
binary_name = images[0]['name']

for thread in threads:
	print "---- Thread", thread['number'], "----"
	if thread['crashed'] is True:
		print "Crashed"
	for stack in thread['stacktrace']:
		if stack['name'] == binary_name:
			load_addr = int(stack['addr'], 0)
			sym_addr = hex(slide_addr - stack_addr + load_addr)
			cmd = subprocess.Popen('/usr/bin/atos -arch ' + arch + ' -o ' + dsym + ' ' + sym_addr, shell=True, stdout=subprocess.PIPE)
			symbol = cmd.stdout.readlines()[0].translate(None, '\n')
			stack['symbol'] = symbol
			print symbol

crashreport = meta
crashreport['threads'] = threads
crashreport['states'] = states
crashreport['images'] = images
