package model_test

import (
	"cwtch.im/cwtch/model"
	"cwtch.im/cwtch/protocol/groups"
	"encoding/base64"
	"git.openprivacy.ca/cwtch.im/tapir/primitives"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("group models", func() {
	var (
		newgroup     *model.Group
		anothergroup *model.Group
		dgm          groups.DecryptedGroupMessage
		alice        primitives.Identity
	)

	BeforeEach(func() {
		newgroup, _ = model.NewGroup("iikv7tizbyxc42rsagnjxss65h3nfiwrkkoiikh7ui27r5xkav7gzuid")
		anothergroup, _ = model.NewGroup("iikv7tizbyxc42rsagnjxss65h3nfiwrkkoiikh7ui27r5xkav7gzuid")

		alice, _ = primitives.InitializeEphemeralIdentity()

		dgm = groups.DecryptedGroupMessage{
			Text:               "hello world",
			Onion:              "some random onion",
			Timestamp:          0,
			SignedGroupID:      nil,
			PreviousMessageSig: nil,
			Padding:            nil,
		}
	})

	Context("on creation of a group", func() {
		It("should pass the cryptographic check", func() {
			Expect(newgroup.CheckGroup()).To(Equal(true))
		})
	})

	Context("after generating an invite", func() {
		It("should validate", func() {
			invite, err := newgroup.Invite()
			Expect(err).NotTo(HaveOccurred())
			anotherGroup, err := model.ValidateInvite(invite)
			Expect(err).NotTo(HaveOccurred())

			Expect(anotherGroup.GroupID).To(Equal(newgroup.GroupID))
			Expect(anotherGroup.GroupName).To(Equal(newgroup.GroupName))
			Expect(anotherGroup.SharedKey).To(Equal(newgroup.GroupKey[:]))
		})
	})

	Context("when encrypting a message", func() {
		Context("decrypting with the same group", func() {
			It("should succeed", func() {
				ciphertext, err := newgroup.EncryptMessage(&dgm)
				Expect(err).NotTo(HaveOccurred())
				success, decryptedMessage := newgroup.DecryptMessage(ciphertext)
				Expect(success).To(Equal(true))
				Expect(decryptedMessage.Text).To(Equal(dgm.Text))
				Expect(decryptedMessage.Onion).To(Equal(dgm.Onion))
			})
		})

		Context("decrypting with a different group", func() {
			It("should fail", func() {
				ciphertext, err := newgroup.EncryptMessage(&dgm)
				Expect(err).NotTo(HaveOccurred())
				success, decryptedMessage := anothergroup.DecryptMessage(ciphertext)
				Expect(success).To(Equal(false))
				Expect(decryptedMessage).To(BeNil())
			})
		})
	})

	Context("when alice encrypts a message to new group", func() {
		It("should succeed and bob should succeed in decrypting it", func() {
			ciphertext, sign, _, err := model.EncryptMessageToGroup("hello world", alice, newgroup, base64.StdEncoding.EncodeToString([]byte("hello world")))
			Expect(err).NotTo(HaveOccurred())
			success, dgm := newgroup.AttemptDecryption(ciphertext, sign)
			Expect(success).To(BeTrue())
			Expect(dgm.Text).To(Equal("hello world"))
		})
	})

	Context("when alice encrypts a message to new group", func() {
		It("should succeed and eve should fail in decrypting it", func() {
			ciphertext, sign, _, err := model.EncryptMessageToGroup("hello world", alice, newgroup, base64.StdEncoding.EncodeToString([]byte("hello world")))
			Expect(err).NotTo(HaveOccurred())
			success, dgm := anothergroup.AttemptDecryption(ciphertext, sign)
			Expect(success).To(BeFalse())
			Expect(dgm).To(BeNil())
		})
	})

	Context("when alice encrypts a message to new group", func() {
		Context("and the server messes with the signature", func() {
			It("bob should be unable to verify the message with the wrong signature", func() {
				ciphertext, _, _, err := model.EncryptMessageToGroup("hello world", alice, newgroup, base64.StdEncoding.EncodeToString([]byte("hello world")))
				Expect(err).NotTo(HaveOccurred())
				success, dgm := newgroup.AttemptDecryption(ciphertext, []byte("bad signature"))
				Expect(success).To(BeFalse())
				Expect(dgm).To(BeNil())
			})
		})
	})

})
