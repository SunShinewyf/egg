'use strict';

module.exports = {
  * bar() {
    this.ctx.body = 'this is obj bar!';
  },

  subObj: {
    * hello() {
      this.ctx.body = 'this is subObj hello!';
    },
  },
};
