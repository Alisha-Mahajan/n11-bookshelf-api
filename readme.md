<img src="./assets/bookshelf-logo.svg" alt="Bookshelf" width="300" height="100">

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Features](#features)
- [Code Features](#code-features)
- [Technology Stack](#technology-stack)
- [Contributors](#contributors)
- [License](#license)
  
# Introduction

Bookshelf is an online bookstore system via which users do not need to blindly go to various places to find required books, they just simply go to Bookshelf and find it. The online bookstore system can not only reduce costs, save time, space, to bring convenience to everyone, but also promote the development of the logistics industry, serving three purposes, mutual benefit. Users can view its details, place an order and then the book is delivered to their address. Users can see their orders placed, their status (delivered date, order placed date), and rate/review their ordered products

Live demo [_here_](https://n11-bookshelf.netlify.app/)

### Sample creds

- For normal user login:  

    Username : guest_bookshelf@gmail.com \
    Password : G*907ues$#t!

- For admin login:

    Username : admin_bookshelf@gmail.com \
    Password : Mnbvcxz@12

Project also provide guest login functionality, just click `LOGIN AS GUEST` button

## Installation

- Clone this repository to your local machine
- Use the `npm i` command to install dependencies
- Inside the root directory run command `npm start` to open the app in your browser of choice
- Several environment variables are needed to run the app. Below are listed:

```plaintext
// port number where app will host
PORT= // optional (defaults to 3000)

MONGODB_URI = // required, mongo db hosted URL
ENCRYPTION_SECRET = // required (encryption secret for JWT)
TOKEN_EXPIRE_TIME = // required (access token expiry time in ms)
REFRESH_TOKEN_EXPIRE_TIME = // required (refresh token expiry time in ms)
STRIPE_SECRET_TEST= // required (stripe payment integration account private key)
AWS_ACCESS_KEY = // required (AWS - S3 account access key for image storage)
AWS_ACCESS_SECRET =  // required (AWS - S3 account access key for image storage)

GUEST_USERNAME= // required, account username used for guest login
GUEST_PASSWORD= // required, guest account password

GMAIL_USERNAME =  // required (app account used for sending mails on successful order creation)
GMAIL_PASSWORD =  // required (app account used for sending mails on successful order creation)

```

## Features

- List of books with details available and options to search, sort and filter are also available so that user can find required book
- Books can be added to cart for later purchase
- Review and rate purchased book
- Order history
- User profile section to view/edit info like name and address

## Code Features

- Login using email & password and Google SSO
- AWS S3 integration for image storage
- Payment gateway integration (stripe)
- Deployment on Heroku

## Technology Stack

![Node.js](https://img.shields.io/badge/Node.js-43853D?style=for-the-badge&logo=node.js&logoColor=white)\
![Mongo](https://img.shields.io/badge/MongoDB-4EA94B?style=for-the-badge&logo=mongodb&logoColor=white)\
![AWS S3](https://img.shields.io/badge/Amazon_AWS-232F3E?style=for-the-badge&logo=amazon-aws&logoColor=white)\
![Heroku](https://img.shields.io/badge/Heroku-430098?style=for-the-badge&logo=heroku&logoColor=white)

## Contributors

<a href="https://github.com/Alisha-Mahajan">Alisha Mahajan</a>\
<a href="https://github.com/SVB-knowmywork">Shubham Bansal</a>

## License

[MIT](/LICENSE)