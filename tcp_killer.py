# Copyright 2017 Google Inc. All Rights Reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Shuts down a TCP connection on Linux or macOS.

Finds the process and socket file descriptor associated with a given TCP
connection. Then injects into that process a call to shutdown()
(http://man7.org/linux/man-pages/man2/shutdown.2.html) that file descriptor,
thereby shutting down the TCP connection.

  Typical usage example:

  tcp_kill("10.31.33.7", 50246 "93.184.216.34", 443)

Dependencies:
  lsof (https://en.wikipedia.org/wiki/Lsof)
  frida (https://www.frida.re/): sudo pip install frida
"""

__author__ = "geffner@google.com (Jason Geffner)"
__version__ = "1.0"


import argparse
import os
import platform
import re
import socket
import subprocess
import threading

import frida


_FRIDA_SCRIPT = """
  var resolver = new ApiResolver("module");
  var lib = Process.platform == "darwin" ? "libsystem" : "libc";
  var matches = resolver.enumerateMatchesSync("exports:*" + lib + "*!shutdown");
  if (matches.length == 0)
  {
    throw new Error("Could not find *" + lib + "*!shutdown in target process.");
  }
  else if (matches.length != 1)
  {
    // Sometimes Frida returns duplicates.
    var address = 0;
    var s = "";
    var duplicates_only = true;
    for (var i = 0; i < matches.length; i++)
    {
      if (s.length != 0)
      {
        s += ", ";
      }
      s += matches[i].name + "@" + matches[i].address;
      if (address == 0)
      {
        address = matches[i].address;
      }
      else if (!address.equals(matches[i].address))
      {
        duplicates_only = false;
      }
    }
    if (!duplicates_only)
    {
      throw new Error("More than one match found for *libc*!shutdown: " + s);
    }
  }
  var shutdown = new NativeFunction(matches[0].address, "int", ["int", "int"]);
  if (shutdown(%d, 0) != 0)
  {
    throw new Error("Call to shutdown() returned an error.");
  }
  send("");
  """


def canonicalize_ip_address(address):
  if ":" in address:
    family = socket.AF_INET6
  else:
    family = socket.AF_INET
  return socket.inet_ntop(family, socket.inet_pton(family, address))


def tcp_kill(local_addr, local_port, remote_addr, remote_port, verbose=False):
  """Shuts down a TCP connection on Linux or macOS.

  Finds the process and socket file descriptor associated with a given TCP
  connection. Then injects into that process a call to shutdown()
  (http://man7.org/linux/man-pages/man2/shutdown.2.html) that file descriptor,
  thereby shutting down the TCP connection.

  Args:
    local_addr: The IP address (as a string) associated with the local endpoint
      of the connection.
    local_port: The port (as an int) associated with the local endpoint of the
      connection.
    remote_addr: The IP address (as a string) associated with the remote
      endpoint of the connection.
    remote_port: The port (as an int) associated with the remote endpoint of the
      connection.
    verbose: If True, print verbose output to the console.

  Returns:
    No return value if successful. If unsuccessful, raises an exception.

  Raises:
    KeyError: Unexpected output from lsof command.
    NotImplementedError: Not running on a Linux or macOS system.
    OSError: TCP connection not found or socket file descriptor not found.
    RuntimeError: Error during execution of JavaScript injected into process.
  """

  if platform.system() not in ("Darwin", "Linux"):
    raise NotImplementedError("This function is only implemented for Linux and "
                              "macOS systems.")

  local_addr = canonicalize_ip_address(local_addr)
  remote_addr = canonicalize_ip_address(remote_addr)

  name_pattern = re.compile(
      r"^\[?(.+?)]?:([0-9]{1,5})->\[?(.+?)]?:([0-9]{1,5})$")
  fd_pattern = re.compile(r"^(\d)+")

  field_names = ("PID", "FD", "NAME")
  fields = {}
  pid = None
  sockfd = None
  for line in subprocess.check_output("lsof -bnlPiTCP -sTCP:ESTABLISHED "
                                      "2>/dev/null", shell=True).splitlines():
    words = line.split()

    if len(fields) != len(field_names):
      for i in xrange(len(words)):
        for field in field_names:
          if words[i] == field:
            fields[field] = i
            break
      if len(fields) != len(field_names):
        raise KeyError("Unexpected field headers in output of lsof command.")
      continue

    name = name_pattern.match(words[fields["NAME"]])
    if not name:
      raise KeyError("Unexpected NAME in output of lsof command.")
    if (int(name.group(2)) == local_port and int(name.group(4)) == remote_port
        and canonicalize_ip_address(name.group(1)) == local_addr and
        canonicalize_ip_address(name.group(3)) == remote_addr):
      pid = int(words[fields["PID"]])
      sockfd = int(fd_pattern.match(words[fields["FD"]]).group(1))
      if verbose:
        print "Process ID of socket's process: %d" % pid
        print "Socket file descriptor: %d" % sockfd
      break

  if not sockfd:
    s = " Try running as root." if os.geteuid() != 0 else ""
    raise OSError("Socket not found for connection." + s)

  _shutdown_sockfd(pid, sockfd)


def _shutdown_sockfd(pid, sockfd):
  """Injects into a process a call to shutdown() a socket file descriptor.

  Injects into a process a call to shutdown()
  (http://man7.org/linux/man-pages/man2/shutdown.2.html) a socket file
  descriptor, thereby shutting down its associated TCP connection.

  Args:
    pid: The process ID (as an int) of the target process.
    sockfd: The socket file descriptor (as an int) in the context of the target
      process to be shutdown.

  Raises:
    RuntimeError: Error during execution of JavaScript injected into process.
  """

  js_error = {}  # Using dictionary since Python 2.7 doesn't support "nonlocal".
  event = threading.Event()

  def on_message(message, data):  # pylint: disable=unused-argument
    if message["type"] == "error":
      js_error["error"] = message["description"]
    event.set()

  session = frida.attach(pid)
  script = session.create_script(_FRIDA_SCRIPT % sockfd)
  script.on("message", on_message)
  closed = False

  try:
    script.load()
  except frida.TransportError as e:
    if str(e) != "the connection is closed":
      raise
    closed = True

  if not closed:
    event.wait()
    session.detach()
  if "error" in js_error:
    raise RuntimeError(js_error["error"])


if __name__ == "__main__":

  class ArgParser(argparse.ArgumentParser):

    def error(self, message):
      print "tcp_killer v" + __version__
      print "by " + __author__
      print
      print "Error: " + message
      print
      print self.format_help().replace("usage:", "Usage:")
      self.exit(0)

  parser = ArgParser(
      add_help=False,
      description="Shuts down a TCP connection on Linux or macOS. Local and "
      "remote endpoint arguments can be copied from the output of 'netstat "
      "-lanW'.",
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog=r"""
Examples:
  %(prog)s 10.31.33.7:50246 93.184.216.34:443
  %(prog)s 2001:db8:85a3::8a2e:370:7334.93 2606:2800:220:1:248:1893:25c8:1946.80
  %(prog)s -verbose [2001:4860:4860::8888]:46820 [2607:f8b0:4005:807::200e]:80
""")

  args = parser.add_argument_group("Arguments")
  args.add_argument("-verbose", required=False, action="store_const",
                    const=True, help="Show verbose output")
  args.add_argument("local", metavar="<local endpoint>",
                    help="Connection's local IP address and port")
  args.add_argument("remote", metavar="<remote endpoint>",
                    help="Connection's remote IP address and port")
  parsed = parser.parse_args()

  ep_format = re.compile(r"^(.+)[:\.]([0-9]{1,5})$")
  local = ep_format.match(parsed.local)
  remote = ep_format.match(parsed.remote)
  if not local or not remote:
    parser.error("Invalid command-line argument.")

  local_address = local.group(1)
  if local_address.startswith("[") and local_address.endswith("]"):
    local_address = local_address[1:-1]

  remote_address = remote.group(1)
  if remote_address.startswith("[") and remote_address.endswith("]"):
    remote_address = remote_address[1:-1]

  tcp_kill(local_address, int(local.group(2)), remote_address,
           int(remote.group(2)), parsed.verbose)

  print "TCP connection was successfully shutdown."
