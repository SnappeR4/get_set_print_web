const { error } = require('console')
const ShowAd = require('../models/Showad')
const fs = require('fs');
const path = require('path');
// Show the list of ShowAd
const index = (req, res, next) => {
    ShowAd.find()
    .then(response => {
        res.json({
            response
        })
    })
    .catch(error => {
        res.json({
            message: 'An error Occured!'
        })
    })
}
// get single ShowAd
const show = (req, res, next) => {
    let ShowAdID = req.body.ShowAdID
    ShowAd.findById(ShowAdID)
    .then(response => {
        res.json({
            response
        })
    })
    .catch(error => {
        res.json({
            message: 'An error Occured!'
        })
    })
}

// add new ShowAd
const store = (req, res, next) => {
  console.log("Received data:", req.body);

  let showAd = new ShowAd({
      image_url: req.body.image_url,
      target_url: req.body.target_url
  });

  showAd.save()
  .then(response => {
      res.json({
          message: 'ShowAd Added Successfully!',
          data: response
      });
  })
  .catch(error => {
      console.error("Error saving ShowAd:", error);
      res.json({
          message: 'An error occurred!',
          error: error.message
      });
  });
};


// update ShowAd
const update = (req, res, next) => {
    let ShowAdID = req.body.ShowAdID
    let updateData = {
        target_url: req.body.target_url,
        image_url: req.body.image_url,
    }
    ShowAd.findByIdAndUpdate(ShowAdID, {$set: updateData})
    .then(response => {
        res.json({
            message: 'ShowAd Updated Successfully!'
        })
    })
    .catch(error => {
        res.json({
            message: 'An error Occured!'
        })
    })
}

const destroy = (req, res, next) => {
    let ShowAdID = req.body.ShowAdID
    ShowAd.findByIdAndDelete(ShowAdID)
    .then(response => {
        res.json({
            message: 'ShowAd Deleted Successfully!'
        })
    })
    .catch(error => {
        res.json({
            message: 'An error Occured!'
        })
    })
}

module.exports = {
    index, show, store, update, destroy
}