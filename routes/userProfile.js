const express = require("express");
const router = express.Router();

const ErrorCodes = require("../core/constants");

const crud = require("../crud/users");
const crudAddress = require("../crud/address");

// GET User's Data
router.get("/", function (req, res, next) {
  // request params
  let _id = req.user._id;

  // making call to mongodb to get user data
  crud
    .getUserById(_id)
    .then((user) => {
      user["password"] = null;
      res.json(user);
    })
    .catch((error) => {
      console.log(error);
      res.status(500).json({
        error: "Internal Server Error.",
      });
    });
});

// POST User's Data
router.post("/", function (req, res, next) {
  // request params
  let user_id = req.user._id;
  const username = req.body.username;

  if (username) {
    crud
      .updateUserName(user_id, username)
      .then(() => res.json({ message: "Profile Updated" }));
  } else {
    res.status(422).json({
      error: "username not provided",
    });
  }
});

// Add new address
router.post("/address", async function (req, res, next) {
  //get user id
  user_id = req.user._id;

  const address = req.body.address;

  if (address) {
    const addressLine1 = address.addressLine1;
    const city = address.city;
    const state = address.state;
    const pincode = address.pincode;

    if (addressLine1 && city && state && pincode) {
      const newAddress = {
        addressLine1,
        city,
        state,
        pincode,
        default: false,
      };
      try {
        const { addresses } = await crudAddress.insertUserAddress(
          user_id,
          newAddress
        );

        return res.json({
          message: "Address added",
          address: addresses.pop(),
        });
      } catch (err) {
        return res.status(ErrorCodes.INTERNAL_SERVER_ERROR).json({
          message: "Error occurred while adding address",
        });
      }
    } else {
      return res.status(ErrorCodes.BAD_REQUEST).json({
        message: "Please provide complete address details",
      });
    }
  } else {
    return res.status(ErrorCodes.BAD_REQUEST).json({
      message: "Please provide address to add",
    });
  }
});

// Edit address
router.patch("/address/:id", function (req, res, next) {
  //get user id
  user_id = req.user._id;
  // request params
  let id = req.params.id;

  const address = req.body.address;

  if (address) {
    const addressLine1 = address.addressLine1;
    const city = address.city;
    const state = address.state;
    const pincode = address.pincode;

    if (addressLine1 && city && state && pincode) {
      const newAddress = {
        addressLine1,
        city,
        state,
        pincode,
        default: false,
      };
      crudAddress.updateUserAddress(user_id, id, newAddress);
      return res.json({
        message: "Address Updated",
      });
    } else {
      return res.status(ErrorCodes.BAD_REQUEST).json({
        message: "Please provide complete address details",
      });
    }
  } else {
    return res.status(ErrorCodes.BAD_REQUEST).json({
      message: "Please provide address to add",
    });
  }
});

module.exports = router;
