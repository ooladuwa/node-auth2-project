const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken")

const restricted = (req, res, next) => {
  const token = req.headers.authorization 
    if(!token) {
      res.status(401).json("Token required")
    } else {
        jwt.verify(jwt, JWT_SECRET, (err, decoded) => {
          if(err) {
            res.status(401).json("Token invalid")
          } else {
            req.decodedToken = decoded
            next()
          }
        })
    }
}

const only = role_name => (req, res, next) => {
  if(req.decodedToken.role_name === role_name) {
    next()
  } else {
    res.status(403).json("This is not for you")
  }
}


const checkUsernameExists = (req, res, next) => {
  const { username } = req.body
  if(username) {
    next()
  } else {
    res.status(401).json("Invalid credentials")
  }
}


const validateRoleName = (req, res, next) => {
  const { role_name } = req.body

  if(role_name) {
    role_name.trim()
    next()
  } else if(!role_name || role_name.trim() === "") {
      "student"
      next()
  } else if(role_name.trim() === "admin") {
      res.status(422).json("Role name can not be admin")
  } else if(role_name.trim().length > 32) {
      res.status(422).json("Role name can not be longer than 32 chars")
  }
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
