const express = require("express");
const aws = require("aws-sdk");
const crypto = require("crypto");
const router = express.Router();
const ErrorCodes = require("../core/constants");
const crud = require("../crud/books");

const aws_bucket_name = "bookshelf-pesto-books";

// Post Book Detail
router.post("/book", async function (req, res, next) {
  // file details
  file = req.files.bookImage;
  let file_id = crypto.randomBytes(20).toString("hex");

  // Setting up S3 upload parameters
  const params = {
    Bucket: aws_bucket_name,
    Key: file_id,
    Body: file.data,
  };

  // initialise aws object
  const s3 = new aws.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_ACCESS_SECRET,
  });

  if (
    !file ||
    !req.body.title ||
    !req.body.author ||
    !req.body.pages ||
    !req.body.description ||
    !req.body.category ||
    !req.body.quantity ||
    !req.body.price ||
    !req.body.language
  ) {
    return res.status(ErrorCodes.BAD_REQUEST).json({
      message: "Please provide all required data",
    });
  }

  try {
    // Uploading file to the bucket
    await s3.upload(params, function (err, data) {
      if (err) {
        return res.status(ErrorCodes.UNPROCESSABLE_ENTITY).json({
          message:
            "Error occurred while uploading image to S3, please try again after sometime.",
        });
      } else {
        s3_link = data.Location;
        data = {
          title: req.body.title,
          author: req.body.author,
          pages: parseInt(req.body.pages),
          description: req.body.description,
          category: req.body.category,
          quantity: parseInt(req.body.quantity),
          price: parseFloat(req.body.price),
          language: req.body.language,
          highlights: req.body.highlights.split(";"),
          imageUri: s3_link,
        };
        result = crud.saveBookDetails(data);
        return res.json({message: "Book details saved."});
      }
    });
  } catch (error) {
    console.log(error);
    return res.status(ErrorCodes.INTERNAL_SERVER_ERROR).json({
      message: "Internal Server Error.",
    });
  }
});

module.exports = router;
