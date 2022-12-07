const port = 8000;
const path = require('path');
require('dotenv').config();

const express = require('express');
const app = express();

const crypto = require("crypto");
const initVector = crypto.randomBytes(16);
const Securitykey = crypto.randomBytes(32);