const {
  time,
  loadFixture,
} = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("MessageStorage", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Network to that snapshot in every test.
  async function deployMessageStorageFixture() {
    const [owner, otherAccount, authorizedContract] = await ethers.getSigners();

    const MessageStorage = await ethers.getContractFactory("MessageStorage");
    const messageStorage = await MessageStorage.deploy();

    return { messageStorage, owner, otherAccount, authorizedContract };
  }

  describe("Deployment", function () {
    it("Should set the right owner", async function () {
      const { messageStorage, owner } = await loadFixture(deployMessageStorageFixture);

      expect(await messageStorage.owner()).to.equal(owner.address);
    });

    it("Should initialize message ID counter to 1", async function () {
        const { messageStorage } = await loadFixture(deployMessageStorageFixture);
        expect(await messageStorage.getTotalMessageCount()).to.equal(0);
    });
  });

  describe("Storage", function () {
    it("Should fail if storage fee is insufficient", async function () {
        const { messageStorage, owner } = await loadFixture(deployMessageStorageFixture);
        const STORAGE_FEE = await messageStorage.STORAGE_FEE();
        
        await expect(
            messageStorage.storeMessage(owner.address, "QmHash", "text", { value: 0 })
        ).to.be.revertedWith("Insufficient storage fee");
    });

    it("Should store a message correctly", async function () {
      const { messageStorage, owner } = await loadFixture(deployMessageStorageFixture);
      const STORAGE_FEE = await messageStorage.STORAGE_FEE();
      const ipfsHash = "QmTestHash123";
      
      await messageStorage.storeMessage(owner.address, ipfsHash, "text", { value: STORAGE_FEE });

      const message = await messageStorage.getMessage(1);
      expect(message.ipfsHash).to.equal(ipfsHash);
      expect(message.sender).to.equal(owner.address);
    });

    it("Should prevent duplicate IPFS hashes", async function () {
        const { messageStorage, owner } = await loadFixture(deployMessageStorageFixture);
        const STORAGE_FEE = await messageStorage.STORAGE_FEE();
        const ipfsHash = "QmDuplicateHash";
        
        await messageStorage.storeMessage(owner.address, ipfsHash, "text", { value: STORAGE_FEE });

        await expect(
            messageStorage.storeMessage(owner.address, ipfsHash, "text", { value: STORAGE_FEE })
        ).to.be.revertedWith("Message already stored");
    });
  });

  describe("Access Control", function () {
      it("Should allow sender to retrieve message", async function () {
          const { messageStorage, owner } = await loadFixture(deployMessageStorageFixture);
          const STORAGE_FEE = await messageStorage.STORAGE_FEE();
          const ipfsHash = "QmAccessTest";

          await messageStorage.storeMessage(owner.address, ipfsHash, "text", { value: STORAGE_FEE });
          
          expect(await messageStorage.retrieveMessage(1)).to.equal(ipfsHash);
      });

      it("Should allow granted user to retrieve message", async function () {
          const { messageStorage, owner, otherAccount } = await loadFixture(deployMessageStorageFixture);
          const STORAGE_FEE = await messageStorage.STORAGE_FEE();
          const ipfsHash = "QmSharedHash";

          await messageStorage.storeMessage(owner.address, ipfsHash, "text", { value: STORAGE_FEE });
          
          // Grant access
          await messageStorage.grantMessageAccess(1, otherAccount.address);

          // Other account retrieves
          expect(await messageStorage.connect(otherAccount).retrieveMessage(1)).to.equal(ipfsHash);
      });

      it("Should deny unauthorized access", async function () {
          const { messageStorage, owner, otherAccount } = await loadFixture(deployMessageStorageFixture);
          const STORAGE_FEE = await messageStorage.STORAGE_FEE();
          const ipfsHash = "QmSecretHash";

          await messageStorage.storeMessage(owner.address, ipfsHash, "text", { value: STORAGE_FEE });
          
          await expect(
              messageStorage.connect(otherAccount).retrieveMessage(1)
          ).to.be.revertedWith("No access to message");
      });
  });
});
