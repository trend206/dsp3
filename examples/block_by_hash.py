from dsp3.models.manager import Manager


dsm = Manager(username="username", password="password", host="127.0.0.1", port="4119")

rules = dsm.list_block_by_hash_rules() # returns json object representing list of Block by Hash Rules

# adds new block by hash rule. based on sha256 file hash.
# The blacklist rules are then applied and enforced on any agent that has AppControl turned on.
dsm.add_block_by_hash_rule("0143f7ba86d17cabdfffdc5247362871ba35ffd431f2c3d314a09b8c568b692a", "Block test.sh File")
dsm.delete_block_by_hash_rule(1) #deletes block by hash rule by rule id

dsm.end_session()