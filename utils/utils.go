package utils

import (
	"encoding/base32"
	"encoding/hex"
	"git.openprivacy.ca/openprivacy/log"
	"strings"
)

// temporary until we do real picture selection
func RandomProfileImage(onion string) string {
	choices := []string{"001-centaur", "002-kraken", "003-dinosaur", "004-tree-1", "005-hand", "006-echidna", "007-robot", "008-mushroom", "009-harpy", "010-phoenix", "011-dragon-1", "012-devil", "013-troll", "014-alien", "015-minotaur", "016-madre-monte", "017-satyr", "018-karakasakozou", "019-pirate", "020-werewolf", "021-scarecrow", "022-valkyrie", "023-curupira", "024-loch-ness-monster", "025-tree", "026-cerberus", "027-gryphon", "028-mermaid", "029-vampire", "030-goblin", "031-yeti", "032-leprechaun", "033-medusa", "034-chimera", "035-elf", "036-hydra", "037-cyclops", "038-pegasus", "039-narwhal", "040-woodcutter", "041-zombie", "042-dragon", "043-frankenstein", "044-witch", "045-fairy", "046-genie", "047-pinocchio", "048-ghost", "049-wizard", "050-unicorn"}
	barr, err := base32.StdEncoding.DecodeString(strings.ToUpper(onion))
	if err != nil || len(barr) != 35 {
		log.Errorf("error: %v %v %v\n", onion, err, barr)
		return "extra/openprivacy.png"
	}
	return "profiles/" + choices[int(barr[33])%len(choices)] + ".png"
}

func RandomGroupImage(handle string) string {
	choices := []string{"001-borobudur", "002-opera-house", "003-burj-al-arab", "004-chrysler", "005-acropolis", "006-empire-state-building", "007-temple", "008-indonesia-1", "009-new-zealand", "010-notre-dame", "011-space-needle", "012-seoul", "013-mosque", "014-milan", "015-statue", "016-pyramid", "017-cologne", "018-brandenburg-gate", "019-berlin-cathedral", "020-hungarian-parliament", "021-buckingham", "022-thailand", "023-independence", "024-angkor-wat", "025-vaticano", "026-christ-the-redeemer", "027-colosseum", "028-golden-gate-bridge", "029-sphinx", "030-statue-of-liberty", "031-cradle-of-humankind", "032-istanbul", "033-london-eye", "034-sagrada-familia", "035-tower-bridge", "036-burj-khalifa", "037-washington", "038-big-ben", "039-stonehenge", "040-white-house", "041-ahu-tongariki", "042-capitol", "043-eiffel-tower", "044-church-of-the-savior-on-spilled-blood", "045-arc-de-triomphe", "046-windmill", "047-louvre", "048-torii-gate", "049-petronas", "050-matsumoto-castle", "051-fuji", "052-temple-of-heaven", "053-pagoda", "054-chichen-itza", "055-forbidden-city", "056-merlion", "057-great-wall-of-china", "058-taj-mahal", "059-pisa", "060-indonesia"}
	barr, err := hex.DecodeString(handle)
	if err != nil || len(barr) == 0 {
		log.Errorf("error: %v %v %v\n", handle, err, barr)
		return "extra/openprivacy.png"
	}
	return "servers/" + choices[int(barr[0])%len(choices)] + ".png"
}
