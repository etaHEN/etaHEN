#! /usr/bin/env python
import array, codecs, time, errno, os, signal, sys, traceback

from math import ceil
from math import floor


if sys.version_info.major < 3:
	print("\nERROR: Python " + str(sys.version_info.major) + " not supported. Please upgrade to Python 3.\n")
	sys.exit(-1)


__WIN32__ = "windows" in str(os.getenv("OS")).lower();

appname = "Binary to Header"
version = "0.3.1"
executable = os.path.basename(__file__)

symbolcp = "©"
if __WIN32__:
	# some characters don't display correctly in Windows console
	symbolcp = "(C)"


# options configured from command parameters
options = {}
options_defaults = {
	"help": {"short": "h", "value": False},
	"version": {"short": "v", "value": False},
	"output": {"short": "o", "value": ""},
	"hname": {"short": "n", "value": ""},
	"chunksize": {"short": "s", "value": 1024 * 1024},
	"nbdata": {"short": "d", "value": 12},
	"datacontent": {"short": "c", "value": False},
	"offset": {"short": "f", "value": 0},
	"length": {"short": "l", "value": 0},
	"pack": {"short": "p", "value": 8},
	"swap": {"short": "e", "value": False},
	"stdvector": {"value": False},
	"eol": {"value": "lf"},
}


## Prints message to console.
#
#  If the `msg` parameter is omitted, `lvl` is used for message
#  `lvl` is used for message text & level defaults to INFO.
#
#  Levels:
#  - q: QUIET (displays message with level info)
#  - i: INFO
#  - w: WARNING
#  - e: ERROR
#
#  @tparam str lvl
#      Message level (or message text if `msg` is omitted).
#  @tparam str msg
#      Message text to be printed.
#  @tparam bool newline
#      If `True` prepend message with newline character
#      (default: `False`).
def printInfo(lvl, msg=None, newline=False):
	if msg == None:
		msg = lvl
		lvl = "i"

	lvl = lvl.lower()
	if lvl in ("q", "quiet"):
		# quiet displays message without level
		lvl = "q"
	elif lvl in ("i", "info"):
		lvl = "INFO"
	elif lvl in ("w", "warn"):
		lvl = "WARNING"
	elif lvl in ("e", "error"):
		lvl = "ERROR"
	elif lvl in ("d", "debug"):
		lvl = "DEBUG"
	else:
		print("ERROR: ({}) Unknown message level: {}".format(printInfo.__name__, lvl))
		sys.exit(errno.EINVAL)

	if lvl != "q":
		msg = "{}: {}".format(lvl, msg)

	if newline:
		msg = "\n{}".format(msg)

	cout = sys.stdout
	if lvl == "ERROR":
		cout = sys.stderr

	cout.write("{}\n".format(msg))


## Prints app name & version.
def printVersion():
	print("\n{} version {} (Python)".format(appname, version)
			+ "\nCopyright {} 2017-2022 Jordan Irwin <antumdeluge@gmail.com>".format(symbolcp))

## Prints usage information.
def printUsage():
	printVersion()
	print("\n  Usage:\n\t{} [options] <file>\n".format(executable)
			+ "\n  Options:"
			+ "\n\t-h, --help\t\tPrint help information & exit."
			+ "\n\t-v, --version\t\tPrint version information & exit."
			+ "\n\t-o, --output\t\tOutput file name."
			+ "\n\t-n, --hname\t\tHeader name. Default is file name with \".\" replaced by \"_\"."
			+ "\n\t-s, --chunksize\t\tRead buffer chunk size (in bytes)."
			+ "\n\t\t\t\t  Default: {} (1 megabyte)".format(getOpt("chunksize", True)[1])
			+ "\n\t-d, --nbdata\t\tNumber of bytes to write per line."
			+ "\n\t\t\t\t  Default: {}".format(getOpt("nbdata", True)[1])
			+ "\n\t-c, --datacontent\tShow data content as comments."
			+ "\n\t-f, --offset\t\tPosition offset to begin reading file (in bytes)."
			+ "\n\t\t\t\t  Default: {}".format(getOpt("offset", True)[1])
			+ "\n\t-l, --length\t\tNumber of bytes to process (0 = all)."
			+ "\n\t\t\t\t  Default: {}".format(getOpt("length", True)[1])
			+ "\n\t-p, --pack\t\tStored data type bit length (8/16/32)."
			+ "\n\t\t\t\t  Default: {}".format(getOpt("pack", True)[1])
			+ "\n\t-e, --swap\t\tSet endianess to big endian for 16 & 32 bit data types."
			+ "\n\t    --stdvector\t\tAdditionally store data in std::vector for C++."
			+ "\n\t    --eol\t\tSet end of line character (cr/lf/crlf)."
			+ "\n\t\t\t\t  Default: {}".format(getOpt("eol", True)[1]))

## Prints message to stderr & exits program.
#
#  @tparam int code
#      Program exit code.
#  @tparam str msg
#      Message to print.
#  @tparam bool show_usage
#      If `True` will print usage info.
def exitWithError(code, msg, show_usage=False):
	printInfo("e", msg, True)
	if show_usage:
		printUsage()
	sys.exit(code)


## Retrieves a configured option.
#
#  @tparam str key
#      Option identifier.
#  @tparam bool default
#      If `True` retrieves default value (default: `False`).
#  @treturn str,str
#      Returns option identifier & configured
#      value (or `None`,`None` if identifier not found).
def getOpt(key, default=False):
	if len(key) == 1:
		key_match = False
		for long_key in options_defaults:
			opt_value = options_defaults[long_key]

			# convert short id to long
			if "short" in opt_value and key == opt_value["short"]:
				key = long_key
				key_match = True
				break

		# invalid short id
		if not key_match:
			return None, None

	if not default and key in options:
		return key, options[key]

	# get default if not configured manually
	if key in options_defaults:
		return key, options_defaults[key]["value"]

	return None, None

## Configures an option from a command line parameter.
#
#  @tparam str key
#      Option identifier.
#  @tparam str value
#      New value to be set.
def setOpt(key, value):
	long_key, default_val = getOpt(key, True)

	# not a valid parameter id
	if long_key == None:
		printInfo("e", "({}) Unknown parameter: {}".format(setOpt.__name__, key))
		traceback.print_stack()
		sys.exit(errno.EINVAL)

	# only compatible types can be set
	opt_type, val_type = type(default_val), type(value)
	if opt_type != val_type:
		printInfo("e", "({}) Value for option \"{}\" must be \"{}\" but found \"{}\""
				.format(setOpt.__name__, long_key, opt_type.__name__, val_type.__name__))
		traceback.print_stack()
		sys.exit(errno.EINVAL)

	options[long_key] = value

## Checks if an argument uses a short ID.
#
#  Does not differenciate between '-a' & '-abcd'.
#
#  @tparam str a
#      String to be checked.
def checkShortArg(a):
	if a.startswith("-") and a.count("-") == 1:
		return a.lstrip("-")

	return None

## Checks if an argument uses a long ID.
#
#  @tparam str a
#      String to be checked.
def checkLongArg(a):
	if a.startswith("--"):
		d_count = 0
		for ch in a:
			if ch != "-":
				break

			d_count = d_count + 1

		if d_count == 2:
			return a.lstrip("-")

	return None

## Parses options from command line.
#
#  @tparam list args
#      Command line arguments.
#  @treturn list
#      Remaining arguments.
def parseCommandLine(args):
	# unparsed arguments
	rem = []

	while len(args) > 0:
		cur_arg = args[0]

		# skip values
		if not cur_arg.startswith("-"):
			if len(args) > 1:
				# FIXME: error code?
				exitWithError(1, "Unknown argument: {}".format(cur_arg))

			rem.append(args.pop(0))
			continue

		res = checkShortArg(cur_arg)
		if res == None:
			res = checkLongArg(cur_arg)

		if res == None and cur_arg.startswith("-"):
			# FIXME: exit code?
			exitWithError(1, "Malformed argument: {}".format(cur_arg))

		if res != None:
			# check if argument is recognized
			key, val_default = getOpt(res, True)
			val_type = type(val_default)

			if val_default == None:
				# FIXME: exit code?
				exitWithError(1, "Unknown argument: {}".format(cur_arg), True)

			if val_type == bool:
				value = True
			else:
				if len(args) < 2:
					# FIXME: exit code?
					exitWithError(1, "\"{}\" requires value".format(cur_arg), True)

				try:
					value = val_type(args[1])
				except ValueError:
					# FIXME: error code?
					exitWithError(1, "\"{}\" value must be of type \"{}\"".format(cur_arg, val_type.__name__))

				# remove value from argument list
				args.pop(1)

			# update config
			setOpt(key, value)
			# remove from argument list
			args.pop(0)

	# input file should be only remaining argument
	return rem


## Removes relative cwd prefix from path.
#
#  @param path
#      String path to be trimmed.
#  @return
#      Trimmed path.
def trimLeadingCWD(path):
	if __WIN32__:
		if path.startswith(".\\"):
			return path.lstrip(".\\")
	elif path.startswith("./"):
		return path.lstrip("./")

	return path


## Normalizes the path node separators for the current system.
#
#  @tparam str path
#      Path to be normalized.
#  @treturn str
#      Path formatted with native directory/node delimeters.
def normalizePath(path):
	if path.strip(" \r\n\t") == "":
		# replace empty path with relative cwd
		return normalizePath("./")

	new_path = path

	if __WIN32__:
		sep = "\\"
		new_path = new_path.replace("/", sep).replace("\\\\", sep)

		if new_path.lower().startswith("\\c\\"):
			new_path = "C:{}".format(new_path[2:])

	else:
		sep = "/"
		new_path = new_path.replace("\\", sep).replace("//", sep)

	# remove redundant node separators
	new_path = new_path.replace("{0}.{0}".format(sep), sep)

	# remove trailing node separator
	new_path = new_path.rstrip(sep)

	return trimLeadingCWD(new_path)


## Concatenates two paths into one.
#
#  @tparam string a
#      Leading path.
#  @tparam string b
#      Trailing path.
#  @return
#      Concatenated path.
def joinPath(a, b):
	return normalizePath("{}/{}".format(a, b))


## Removes path to parent directory from path name.
#
#  @tparam str path
#      Path to be parsed.
#  @treturn str
#      Name of last node in path.
def getBaseName(path):
	base_name = os.path.basename(path)

	# MSYS versions of Python appear to not understand Windows paths
	if __WIN32__ and "\\" in base_name:
		base_name = base_name.split("\\")[-1]

	return base_name


## Removes last node from path name.
#
#  @tparam str path
#      Path to be parsed.
#  @treturn
#      Path to parent directory.
def getDirName(path):
	dir_name = os.path.dirname(path)

	# MSYS versions of Python appear to not understand Windows paths
	if not dir_name and __WIN32__:
		dir_name = "\\".join(path.split("\\")[:-1])

	return dir_name


cancelled = False

## Handles Ctrl+C press.
def sigintHandler(signum, frame):
	print("\nSignal interrupt caught, cancelling ...")
	global cancelled
	cancelled = True

	# reset handler to catch SIGINT next time
	signal.signal(signal.SIGINT, sigintHandler)


## Formats duration for printing.
#
#  @tparam float ts
#      Process start timestamp (sec.ms).
#  @tparam float te
#      Process end timestamp (sec.ms).
#  @return
#      String formatted for readability.
def formatDuration(ts, te):
	duration = te - ts
	dmsg = ""

	dsec = floor(duration)
	if dsec < 1:
		dmsg += "{} ms".format(round(duration * 1000))
	else:
		dmin = floor(dsec / 60)
		if dmin > 0:
			dmsg += "{} min".format(dmin)
			dsec = dsec % (dmin * 60)
			if dsec > 0:
				dmsg += " {} sec".format(dsec)
		else:
			dmsg += "{} sec".format(dsec)

	return dmsg


## Converts non-printable characters to ".".
#
#  @tparam byte c
#      Character to evaluate.
#  @return
#      Same character or "." non-printable.
def toPrintableChar(c):
	if type(c) == str:
		c = ord(c)

	if c >= ord(" ") and c <= ord("~"):
		return chr(c)

	return "."


## Reads data from input & writes header.
#
#  @tparam str fin
#      Path to file to be read.
#  @tparam str fout
#      Path to file to be written.
#  @tparam[opt] str hname
#      Text to be used for header definition & array variable name.
#  @tparam[opt] bool stdvector
#      Flag to additionally store data in C++ std::vector.
def convert(fin, fout, hname="", stdvector=False):
	outlen = getOpt("pack")[1]
	if (outlen > 32 or outlen % 8 != 0):
		exitWithError(-1, "Unsupported pack size, must be 8, 16, or 32")

	swap_bytes = getOpt("swap")[1]

	# check if file exists
	if not os.path.isfile(fin):
		exitWithError(errno.ENOENT, "File \"{}\" does not exist".format(fin))

	# set EOL
	eol = "\n" # default
	newEol = getOpt("eol")[1].lower()
	if newEol == "cr":
		eol = "\r"
	elif newEol == "crlf":
		eol = "\r\n"
	elif newEol != "lf":
		printInfo("w", "Unknown EOL type \"{}\", using default \"lf\"\n".format(newEol), True)

	# columns per line
	cols = getOpt("nbdata")[1]

	# show data content in comments
	showDataContent = getOpt("datacontent")[1]

	target_basename = list(getBaseName(fout))
	target_dir = getDirName(fout)
	if not target_dir.strip():
		# use working dirkectory if parent cannot be parsed
		target_dir = normalizePath("./")

	if os.path.isfile(target_dir):
		# FIXME: error code?
		exitWithError(1, "Cannot write to dir \"{}\", file exists".format(target_dir))
	elif not os.path.isdir(target_dir):
		exitWithError(errno.ENOENT, "Cannot write to dir \"{}\", does not exist".format(target_dir))

	badchars = ("\\", "+", "-", "*", " ")

	# don't allow use of all unusable characters in header name
	if hname.strip(" \t\r\n" + "".join(badchars)):
		hname = list(hname)
	else:
		# use source filename as default
		hname = list(getBaseName(fin))

	# remove unwanted characters
	for x in range(len(hname)):
		if hname[x] in badchars or hname[x] == ".":
			hname[x] = "_"
	for x in range(len(target_basename)):
		if target_basename[x] in badchars:
			target_basename[x] = "_"

	# prefix with '_' when first char is a number
	if hname[0].isnumeric():
		hname.insert(0, "_")

	target_basename = "".join(target_basename)
	hname = "".join(hname)
	fout = joinPath(target_dir, target_basename)

	# uppercase name for header
	hname_upper = hname.upper()
	hname_upper += "_H"

	data_length = os.path.getsize(fin)
	wordbytes = int(outlen / 8)

	offset = getOpt("offset")[1]
	if offset > data_length:
		print("ERROR: offset bigger than file length")
		return -1

	# amount of bytes to process
	process_bytes = getOpt("length")[1]
	bytes_to_go = data_length - offset
	if process_bytes > 0 and process_bytes < bytes_to_go:
		bytes_to_go = process_bytes

	# check if there are any bytes to omit during packing
	# FIXME: incomplete words not processed
	omit = bytes_to_go % (outlen / 8)
	if omit:
		printInfo("w", "Last {} byte(s) will be ignored as not forming full data word".format(omit))
		bytes_to_go -= omit

	chunk_size = getOpt("chunksize")[1]
	chunk_count = ceil((data_length - offset) / chunk_size)

	if chunk_size % wordbytes:
		printInfo("w", "Chunk size truncated to full words length")
		chunk_size -= chunk_size % wordbytes;

	print("File size:  {} bytes".format(data_length))
	print("Chunk size: {} bytes".format(chunk_size))
	if offset:
		print("Start from position: {}".format(offset))
	if process_bytes:
		print("Process maximum {} bytes".format(process_bytes))
	if outlen != 8:
		print("Pack into {} bit ints".format(outlen))

	# *** START: read/write *** #

	# declare read/write streams
	ofs, ifs = None, None
	bytes_written = 0

	starttime = time.time()

	try:
		# set signal interrupt (Ctrl+C) handler
		signal.signal(signal.SIGINT, sigintHandler)

		# open file stream for writing
		ofs = codecs.open(fout, "w", "utf-8")

		text = "#ifndef {0}{1}#define {0}{1}".format(hname_upper, eol)
		if stdvector:
			text += "{0}#ifdef __cplusplus{0}#include <vector>{0}#endif{0}".format(eol)

		data_type = "char"
		if outlen == 32:
			data_type = "int"
		elif outlen == 16:
			data_type = "short"
		text += "{0}static const unsigned {1} {2}[] = {{{0}".format(eol, data_type, hname)

		ofs.write(text)

		# open file stream for reading
		ifs = codecs.open(fin, "rb")

		# empty line
		print()

		# how many bytes to write
		bytes_to_go = data_length - offset;
		if process_bytes > 0 and process_bytes < bytes_to_go:
			bytes_to_go = process_bytes

		# check if there are any bytes to omit during packing
		# FIXME: incomplete words not processed
		omit = bytes_to_go % (outlen / 8);
		if omit:
			printInfo("w", "Last {} byte(s) will be ignored as not forming full data word".format(omit))
			bytes_to_go -= omit;

		eof = False # to check if we are at the end of file
		comment = ""
		for chunk_idx in range(chunk_count):
			if eof or cancelled:
				break;

			sys.stdout.write("\rWriting chunk {} out of {} (Ctrl+C to cancel)"
					.format(chunk_idx + 1, chunk_count))

			if bytes_written == 0:
				ifs.seek(offset)
			else:
				ifs.seek(ifs.tell())
			chunk = array.array("B", ifs.read(chunk_size))

			byte_idx = 0
			while byte_idx < len(chunk):
				if eof or cancelled:
					break

				if bytes_written % (cols * wordbytes) == 0:
					ofs.write("\t")
					comment = ""

				byte_order = range(0, wordbytes)
				if swap_bytes:
					byte_order = reversed(byte_order)

				word = ""
				for i in byte_order:
					word += "%02x" % chunk[byte_idx + i]
				byte_idx += wordbytes

				if showDataContent:
					comment += toPrintableChar(chunk[byte_idx - 1])

				ofs.write("0x{}".format(word))
				bytes_written += wordbytes

				if bytes_written >= bytes_to_go:
					eof = True
					if showDataContent:
						for i in range(bytes_written % (cols * wordbytes), (cols * wordbytes)):
							ofs.write("      ")
						ofs.write("  /* {} */".format(comment))
					ofs.write(eol)
				else:
					if bytes_written % (cols * wordbytes) == 0:
						ofs.write(",")
						if showDataContent:
							ofs.write(" /* {} */".format(comment))
						ofs.write(eol)
					else:
						ofs.write(", ")

		# close file read stream
		ifs.close()
		if cancelled:
			# close write stream & exit
			ofs.close()
			return errno.ECANCELED

		# empty line
		print("\n")

		text = "}};{0}".format(eol)
		if stdvector:
			text += "{0}#ifdef __cplusplus{0}static const std::vector<char> ".format(eol) \
			+ hname + "_v(" + hname + ", " + hname + " + sizeof(" + hname \
			+ "));{0}#endif{0}".format(eol)
		text +="{0}#endif /* {1} */{0}".format(eol, hname_upper)

		ofs.write(text)

		# close file write stream
		ofs.close()

	except Exception as e:
		# close read/write streams
		if ofs:
			ofs.close()
		if ifs:
			ifs.close()

		err = -1
		msg = ["\nAn error occurred during read/write."]
		for eparam in e.args:
			ptype = type(eparam)
			if ptype == int and err < 0:
				err = eparam

		if err > 0:
			msg[0] = "{} Code: {}".format(msg[0], err)

		print("\n".join(msg))
		traceback.print_exc()
		return err

	endtime = time.time()

	# *** END: read/write *** #

	print("Bytes written: {}".format(bytes_written))
	print("Time elapsed:  {}".format(formatDuration(starttime, endtime)))
	print("Exported to:   {}".format(fout))

	return 0


## Main function called at program start.
#
#  @tparam list argv
#      Command line arguments.
def main(argv):
	argc = len(argv)
	argv = parseCommandLine(argv)

	if getOpt("help")[1]:
		printUsage()
		return 0

	if getOpt("version")[1]:
		printVersion()
		return 0

	if len(argv) == 0:
		exitWithError(1, "Missing <file> argument", True)

	# file to read
	source_file = argv[0]
	argv.pop(0)

	if len(argv) > 0:
		printInfo("w", "Some command arguments were not parsed: {}".format(argv))

	source_basename = getBaseName(source_file)

	# file to write
	target_file = getOpt("output")[1]
	if not target_file.strip():
		# use source file to define default target file
		target_file = os.path.join(getDirName(source_file), source_basename + ".h")

	return convert(source_file, target_file, getOpt("hname")[1], getOpt("stdvector")[1])


# program entry point.
if __name__ == "__main__":
	# remove executable name from arguments passed to main function
	sys.exit(main(sys.argv[1:]))