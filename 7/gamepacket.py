from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, BUFFER, LIST, UINT32, UINT16

#class GameCommandPacket(PacketType):
#    DEFINITION_IDENTIFIER = "game command packet"
#    DEFINITION_VERSION = "1.0"
#
#    FIELDS = [
#        ("cmd", STRING)
#    ]
#
#    @classmethod
#    def create_game_command_packet(cls, s):
#        obj = cls()
#        obj.cmd = s
#        return obj
#
#    def command(self):
#        #MUST RETURN A STRING
#        return self.cmd
#
#class GameResponsePacket(PacketType):
#    DEFINITION_IDENTIFIER = "game response packet"
#    DEFINITION_VERSION = "1.0"
#
#    FIELDS = [
#        ("resp", STRING),
#        ("stat", STRING)
#    ]
#
#    @classmethod
#    def create_game_response_packet(cls, response, status):
#        obj = cls()
#        obj.resp = response
#        obj.stat = status
#        return obj
#
#    def game_over(self):
#        #MUST RETURN A BOOL
#        if ("escaped" in self.stat) or ("dead" in self.stat):
#            return True
#        else:
#            return False
#
#    def status(self):
#        return self.stat
#
#    def response(self):
#        return self.resp


def create_game_init_packet(username):
    ''' Returns packet for initiating game '''
    return CreateGameInitPacket.create_gInit_pkt(username)

def process_game_init(pkt):
    ''' Returns the username '''
    if isinstance(pkt, CreateGameInitPacket):
        return pkt.get_username()
    else:
        raise TypeError('invalid packet type')

def create_game_require_pay_packet(unique_id, account, amount):
    ''' produce a packet that requests a particular amount from the bank '''
    return CreateGameRequirePayPacket.create_gRequirePay_pkt(unique_id,account,amount)

def process_game_require_pay_packet(pkt): 
    ''' that will return the unique id, the deposit account, and the amount. '''
    if isinstance(pkt, CreateGameRequirePayPacket):
        return pkt.get_uid(), pkt.get_account(), pkt.get_amount()
    else:
        raise TypeError('invalid packet type')

def create_game_pay_packet(receipt, receipt_signature): 
    ''' that will produce a packet proving payment. '''
    return CreateGamePayPacket.create_gPay_pkt(receipt, receipt_signature)

def process_game_pay_packet(pkt): 
    ''' that will return the receipt and receipt signature from the packet. '''
    if isinstance(pkt, CreateGamePayPacket):
        return pkt.get_receipt(), pkt.get_receipt_signature()
    else:
        raise TypeError('invalid packet type')

def create_game_response(response, status):
    ''' that will produce game responses with the textual response and the status '''
    return CreateGameResponsePacket.create_gResponse_pkt(response, status)

def process_game_response(pkt): 
    ''' that will return the game response and the status '''
    if isinstance(pkt, CreateGameResponsePacket):
        return pkt.get_response(), pkt.get_stat()
    else:
        raise TypeError('invalid packet type')

def create_game_command(command): 
    ''' that will produce a game command '''
    return CreateGameCommandPacket.create_game_command_packet(command)

def process_game_command(pkt):
    ''' that will return the game command '''
    if isinstance(pkt, CreateGameCommandPacket):
        return pkt.get_command()
    else:
        raise TypeError('invalid packet type')


class CreateGameInitPacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.creategameinit"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("username", STRING)
    ]

    @classmethod
    def create_gInit_pkt(cls, s):
        obj = cls()
        obj.username = s
        return obj

    def get_username(self):
        return self.username

class CreateGameRequirePayPacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.creategamerequirepay"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("unique_id", STRING),
        ("account", STRING),
        ("amount", UINT16)
    ]

    @classmethod
    def create_gRequirePay_pkt(cls, uid, account, amount):
        obj = cls()
        obj.unique_id = uid
        obj.account = account
        obj.amount = int(amount)
        return obj

    def get_uid(self):
        return self.unique_id

    def get_account(self):
        return self.account

    def get_amount(self):
        return self.amount

class CreateGamePayPacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.creategamepay"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("receipt", BUFFER),
        ("receipt_signature", BUFFER)
    ]

    @classmethod
    def create_gPay_pkt(cls, receipt, receipt_sign):
        obj = cls()
        obj.receipt = receipt
        obj.receipt_signature = receipt_sign
        return obj

    def get_receipt(self):
        return self.receipt

    def get_receipt_signature(self):
        return self.receipt_signature

class CreateGameResponsePacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.creategameresponse"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("response", STRING),
        ("stat", STRING)
    ]

    @classmethod
    def create_gResponse_pkt(cls, response, stat):
        obj = cls()
        obj.response = response
        obj.stat = stat
        return obj

    def get_response(self):
        return self.response

    def get_stat(self):
        return self.stat

class CreateGameCommandPacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.creategamecommand"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("cmd", STRING)
    ]
    @classmethod
    def create_game_command_packet(cls, s):
        obj = cls()
        obj.cmd = s
        return obj

    def get_command(self):
        return self.cmd

