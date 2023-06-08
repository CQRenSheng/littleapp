/* eslint-disable block-scoped-var */
/* eslint-disable class-methods-use-this */
import fs from 'fs';
import request from 'request';
import nodeutil from 'util';
import moment from 'moment'
import rq from 'request-promise';
import { domain } from '../config/config';
import { platformService, platformApi } from '../services/platform'

const gm = require('gm');
const crypto = require('crypto');
const xml = require('./xmltool')

const wxapis = {
  apiDomain: 'https://api.weixin.qq.com/',
  apiURL: {
    // accessToken
    accessTokenApi: '%scgi-bin/token?grant_type=client_credential&appid=%s&secret=%s',
    // accessJsticket
    accessJsticket: '%scgi-bin/ticket/getticket?access_token=%s&type=jsapi',
    // 自定义菜单
    createMenu: '%scgi-bin/menu/create?access_token=%s',
    // 图文内的图片地址获取接口地址
    uploadImg: '%scgi-bin/media/uploadimg?access_token=%s&type=image',
    // 图文封面图片获取接口地址
    uploadImgMedia: '%scgi-bin/media/upload?access_token=%s&type=image',
    // 上传图文消息素材
    uploadNews: '%scgi-bin/media/uploadnews?access_token=%s',
    // 群发接口地址
    sendNewsMsg: '%scgi-bin/message/mass/sendall?access_token=%s',
    // 预览群发消息接口
    previewMsg: '%scgi-bin/message/mass/preview?access_token=%s',
    // 获取图文群发每日数据
    getarticlesummary: '%sdatacube/getarticlesummary?access_token=%s',
    // 获取图文群发总数据
    getarticletotal: '%sdatacube/getarticletotal?access_token=%s',
    // 获取图文统计数据
    getuserread: '%sdatacube/getuserread?access_token=%s',
    // 获取图文统计分时数据
    getuserreadhour: '%sdatacube/getuserreadhour?access_token=%s',
    // 获取图文分享转发数据
    getusershare: '%sdatacube/getusershare?access_token=%s',
    // 获取图文分享转发分时数据
    getusersharehour: '%sdatacube/getusersharehour?access_token=%s',
    // 登录凭证校验
    authcode2Session: '%ssns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=%s',
    // 发送模板消息
    template: '%scgi-bin/message/wxopen/template/send?access_token=%s',
    // 获取小程序码，适用于需要的码数量极多的业务场景。通过该接口生成的小程序码，永久有效，数量暂无限制。
    getwxacodeunlimit: '%swxa/getwxacodeunlimit?access_token=%s',

  },
}
const qywxapis = {
  apiDomain: 'https://qyapi.weixin.qq.com/',
  apiURL: {
    // accessToken
    accessTokenApi: '%scgi-bin/gettoken?corpid=%s&corpsecret=%s',
    // authcode2Session
    authcode2Session: '%scgi-bin/miniprogram/jscode2session?access_token=%s&js_code=%s&grant_type=%s',
  },
}

class WeChat {
  constructor(config) {
    // 设置 WeChat 对象属性 config
    this.config = config;
    // 设置 WeChat 对象属性 token
    this.token = config.token;
    // 设置 WeChat 对象属性 appID
    this.appID = config.appID;
    // 设置 WeChat 对象属性 appScrect
    this.appSecret = config.appSecret;
  }
  // 下载网络图片
  static downImg(opts = {}, path = '') {
    return new Promise((resolve) => {
      request
        .get(opts)
        .on('response', (response) => {
          console.log('img type:', response.headers['content-type'])
        })
        .pipe(fs.createWriteStream(path))
        .on('error', (e) => {
          console.log('pipe error', e)
          resolve('error');
        })
        .on('finish', () => {
          console.log('downImg finish:', path);
          console.log('执行压缩图片开始', path);
          gm(path).quality(40).write(path, () => {
            console.log('压缩图片完成', path);
            resolve('ok');
          });
          console.log('执行压缩图片结束', path);
        })
    })
  }
  // 请求函数
  async request(options) {
    const self = this;
    const reqOpt = options;
    if (!reqOpt.url) {
      return
    }
    reqOpt.headers = { 'User-Agent': 'request' };
    reqOpt.json = true;
    reqOpt.token = self.token;
    if (!options.method) {
      reqOpt.method = 'GET'
    }
    return rq(reqOpt).then(parsedResult => parsedResult).catch((err) => {
      throw new Error(err)
    });
  }
  // 微信接入验证
  async auth(ctx) {
    const {
      // 1.获取微信服务器Get请求的参数 signature、timestamp、nonce、echostr
      signature, timestamp, nonce,
    } = ctx.request.query;
    // 2.将token、timestamp、nonce三个参数进行字典序排序
    const tempArray = [this.token, timestamp, nonce];
    tempArray.sort();
    // 3.将三个参数字符串拼接成一个字符串进行sha1加密
    const tempStr = tempArray.join('');
    // 创建加密类型
    const hashCode = crypto.createHash('sha1');
    // 对传入的字符串进行加密
    const resultCode = hashCode.update(tempStr, 'utf8').digest('hex');
    // 4.开发者获得加密后的字符串可与signature对比，标识该请求来源于微信
    if (resultCode === signature) {
      return true;
    }
    return false;
  }
  // 获取AccessToken
  async getAccessToken(callmethod, type = 'dyh') {
    if (callmethod) {
      console.log('getAccessToken callmethod:', callmethod);
    }
    const self = this;
    const rsAccess = {
      success: true,
      message: '',
      access_token: '',
    }
    const result = await platformService.request({
      uri: platformApi.wx.access,
      qs: {
        access_type: 'access',
        type,
      },
    });
    const DBToken = result.data;
    // console.log('>>>>>>>>>>>>>>>>>>> DBToken:', DBToken);
    if (DBToken && DBToken.access_token !== '') {
      rsAccess.access_token = DBToken.access_token
      return rsAccess
    }
    // 格式化请求地址
    const url = nodeutil.format(wxapis.apiURL.accessTokenApi, wxapis.apiDomain, self.appID, self.appSecret);
    console.log('>>>>>>>>>>>>>>>>>>> 格式化请求地址:', url);
    const rs = await self.request({ url });
    console.log('>>>>>>>>>>>>>>>>>>> 请求结果:', rs);
    if (rs.errcode) {
      rsAccess.success = false;
      rsAccess.message = rs.errmsg;
      return rsAccess
    }
    // 1.8小时.微信过期2个小时。提现10分钟以避免网络或操作延时导致的accesstoken过期.
    const expirestime = moment().add(1.8, 'hour').format('YYYY-MM-DD HH:mm:ss')
    const insRel = await platformService.request({
      uri: platformApi.wx.access,
      method: 'post',
      body: {
        access_type: 'access',
        access_token: rs.access_token,
        expires_time: expirestime,
        type,
      },
    });
    const rssave = insRel.data;
    console.log('>>>>>>>>>>>>>>>>>>> 增加数据:', rssave);
    if (!rssave) {
      rsAccess.success = false;
      rsAccess.message = 'DB save error';
      return rsAccess
    }
    rsAccess.access_token = rs.access_token
    // console.log('getAccessToken access_token', rsAccess)
    return rsAccess
  }
  // 获取accessJsticket
  async getJsApiTicket() {
    const self = this;
    const rsTicket = {
      success: true,
      message: '',
      ticket: '',
    }
    const result = await platformService.request({
      uri: platformApi.wx.access,
      qs: {
        access_type: 'jsapi',
      },
    });
    const DBTicket = result.data;
    if (DBTicket && DBTicket.access_token !== '') {
      rsTicket.ticket = DBTicket.access_token
      return rsTicket
    }
    // 格式化请求地址
    const rsAccess = await self.getAccessToken('getJsApiTicket')
    if (!rsAccess.success) {
      rsTicket.success = false;
      rsTicket.message = 'WX_ACCESSTOKEN_ERROR';
      return
    }
    const url = nodeutil.format(wxapis.apiURL.accessJsticket, wxapis.apiDomain, rsAccess.access_token);
    const rs = await self.request({ url });
    if (rs.errcode) {
      rsTicket.success = false;
      rsTicket.message = rs.errmsg;
      return rsTicket
    }
    // 1.8小时.微信过期2个小时。提现10分钟以避免网络或操作延时导致的accesstoken过期.
    const expirestime = moment().add(1.8, 'hour').format('YYYY-MM-DD HH:mm:ss')
    const insRel = await platformService.request({
      uri: platformApi.wx.access,
      method: 'post',
      body: {
        access_type: 'jsapi',
        access_token: rs.ticket,
        expires_time: expirestime,
      },
    });
    const rssave = insRel.data;
    if (!rssave) {
      rsTicket.success = false;
      rsTicket.message = 'DB save error';
      return rsTicket
    }
    rsTicket.ticket = rs.ticket
    console.log('getJsApiTicket result', rsTicket)
    return rsTicket
  }
  // 获取签名
  async GetSignPackage(ctx) {
    const self = this;
    const jsapiticket = await self.getJsApiTicket()
    if (!jsapiticket.success) {
      return ctx.error('WX_ACCESSTOKEN_ERROR');
    }
    const nonceStr = self.createNonceStr(16)
    const timestamp = Math.floor(Date.now() / 1000) // 精确到秒
    const { urlpath: url } = ctx.request.query;
    const rawString = `jsapi_ticket=${jsapiticket.ticket}&noncestr=${nonceStr}&timestamp=${timestamp}&url=${url}`;
    const hashCode = crypto.createHash('sha1');
    // 对传入的字符串进行加密
    const signature = hashCode.update(rawString, 'utf8').digest('hex');
    const signPackage = {
      appId: self.appID, nonceStr, timestamp, url, signature, rawString,
    }
    return signPackage;
  }
  // 自定义菜单
  async customMenu(menudata, ctx) {
    const self = this;
    const rsAccess = await self.getAccessToken('customMenu')
    if (!rsAccess.success) {
      ctx.error('WX_ACCESSTOKEN_ERROR');
      return
    }
    // 格式化请求连接
    const url = nodeutil.format(wxapis.apiURL.createMenu, wxapis.apiDomain, rsAccess.access_token);
    const requestOpt = {
      url,
      method: 'POST',
      body: menudata,
    }
    console.log('menuData:', menudata)
    const rs = await self.request(requestOpt);
    return rs
  }
  // 上传图片
  async uploadImg(imgpath, ctx) {
    const self = this;
    const rsAccess = await self.getAccessToken('uploadImg')
    if (!rsAccess.success) {
      return ctx.error('WX_ACCESSTOKEN_ERROR');
    }
    // 格式化请求连接
    const url = nodeutil.format(wxapis.apiURL.uploadImg, wxapis.apiDomain, rsAccess.access_token);
    const requestOpt = {
      url,
      method: 'POST',
      formData: {
        media: {
          value: fs.createReadStream(imgpath),
          options: {
            filename: 'test.jpg',
            contentType: 'image/jpg',
          },
        },
      },
    }
    const rs = await self.request(requestOpt);
    // 上传成功后删除本地文件
    if (fs.existsSync(imgpath)) {
      fs.unlinkSync(imgpath, (err) => {
        if (err) console.log(err);
      });
    }
    return rs
  }
  // 上传永久图片
  async uploadImgMedia(imgpath, ctx) {
    const self = this;
    const rsAccess = await self.getAccessToken('uploadImgMedia')
    if (!rsAccess.success) {
      return ctx.error('WX_ACCESSTOKEN_ERROR');
    }
    // 格式化请求连接
    const url = nodeutil.format(wxapis.apiURL.uploadImgMedia, wxapis.apiDomain, rsAccess.access_token);
    const requestOpt = {
      url,
      method: 'POST',
      formData: {
        media: {
          value: fs.createReadStream(imgpath),
          options: {
            filename: 'test.jpg',
            contentType: 'image/jpg',
          },
        },
      },
    }
    const rs = await self.request(requestOpt);
    // 上传成功后删除本地文件
    if (fs.existsSync(imgpath)) {
      fs.unlinkSync(imgpath, (err) => {
        if (err) console.log(err);
      });
    }
    return rs
  }
  // 上传新闻
  async uploadNews(articlesData, ctx) {
    const self = this;
    const rsAccess = await self.getAccessToken('uploadNews')
    if (!rsAccess.success) {
      return ctx.error('WX_ACCESSTOKEN_ERROR');
    }
    // 格式化请求连接
    const url = nodeutil.format(wxapis.apiURL.uploadNews, wxapis.apiDomain, rsAccess.access_token);
    const requestOpt = {
      url,
      method: 'POST',
      body: articlesData,
    }
    console.log('>>>>>>>>>>>>>>>>>>> 格式化请求地址:', url);
    const rs = await self.request(requestOpt);
    return rs
  }
  // 群发新闻接口地址
  async sendNewsMsg(mpnewsmedia, ctx) {
    const self = this;
    const rsAccess = await self.getAccessToken('sendNewsMsg')
    if (!rsAccess.success) {
      return ctx.error('WX_ACCESSTOKEN_ERROR');
    }
    // 格式化请求连接
    const url = nodeutil.format(wxapis.apiURL.sendNewsMsg, wxapis.apiDomain, rsAccess.access_token);
    const requestOpt = {
      url,
      method: 'POST',
      body: {
        filter: {
          is_to_all: true,
        },
        mpnews: {
          media_id: mpnewsmedia,
        },
        msgtype: 'mpnews',
        send_ignore_reprint: 1,
      },
    }
    const rs = await self.request(requestOpt);
    return rs
  }
  // 预览
  async previewMsg(mpnewsmedia, towxname, ctx) {
    const self = this;
    const rsAccess = await self.getAccessToken('previewMsg')
    if (!rsAccess.success) {
      return ctx.error('WX_ACCESSTOKEN_ERROR');
    }
    // 格式化请求连接
    const url = nodeutil.format(wxapis.apiURL.previewMsg, wxapis.apiDomain, rsAccess.access_token);
    const requestOpt = {
      url,
      method: 'POST',
      body: {
        towxname,
        mpnews: {
          media_id: mpnewsmedia,
        },
        msgtype: 'mpnews',
      },
    }
    const rs = await self.request(requestOpt);
    return rs
  }
  // 关注回复
  async receiveEvent(eventobj) {
    // 公众账号原始ID eventobj->ToUserName;
    // 关注者openid eventobj->FromUserName
    const self = this;
    let content = '';
    if (eventobj.Event && eventobj.Event[0] === 'subscribe') {
      // 获取图文消息
      const result = await platformService.request({
        uri: platformApi.wx.autoreply,
        qs: {
          type: 'dyh',
        },
      });
      const replyContent = result.data;
      if (!replyContent) { return '' }
      const newsContent = [{
        Title: replyContent.title,
        Description: replyContent.desc,
        PicUrl: replyContent.pic,
        Url: `${domain}/wxautoreply`,
      }]
      content = self.transmitNews(eventobj, newsContent);
    }
    return content;
  }
  // 发送模版消息
  async templateSend(ctx, body) {
    console.log('>>>>>>>>>>>>>>>>>>> 发送模版消息');
    const self = this;
    const rsAccess = await self.getAccessToken('templateSend', 'xcx')
    if (!rsAccess.success) {
      return ctx.error('WX_ACCESSTOKEN_ERROR');
    }
    console.log('>>>>>>>>>>>>>>>>>>> getAccessToken 结束');
    const url = nodeutil.format(wxapis.apiURL.template, wxapis.apiDomain, rsAccess.access_token);
    const requestOpt = {
      url,
      method: 'POST',
      header: {
        'Content-Type': 'application/json',
      },
      body,
    };
    console.log('>>>>>>>>>>>>>>>>>>> 请求参数：', requestOpt);
    const result = await self.request(requestOpt);
    console.log('>>>>>>>>>>>>>>>>>>> 发送模版消息，结果result：', result);
    if (result.errcode === 0) {
      return {
        success: true,
        msg: '发送成功！',
      };
    }
    return {
      success: false,
      msg: result.errMsg,
    };
  }
  // 接收文字消息
  async receiveText(textobj) {
    const result = this.transmitText(textobj, moment().format('YYYY-MM-DD HH:mm:ss'));
    return result;
  }
  // 回复文字消息
  async transmitText(transmitObj, textcontent) {
    const returnJson = {
      xml: {
        ToUserName: transmitObj.FromUserName,
        FromUserName: transmitObj.ToUserName,
        CreateTime: Date.now(),
        MsgType: 'text',
        Content: textcontent,
      },
    }
    return xml.jsonToXml(returnJson)
  }
  // 回复图文消息
  async transmitNews(transmitObj, newsContent) {
    if (!newsContent || newsContent.length === 0) {
      return ''
    }
    if (newsContent.length > 8) {
      return ''
    }
    // Title图文消息标题
    // Description图文消息描述
    // PicUrl图片链接，支持JPG、PNG格式，较好的效果为大图360*200，小图200*200
    // Url点击图文消息跳转链接
    const ArticlesArr = {
      item: [],
    };
    newsContent.forEach((element) => {
      ArticlesArr.item.push({
        ...element,
      })
    });
    const returnJson = {
      xml: {
        ToUserName: transmitObj.FromUserName,
        FromUserName: transmitObj.ToUserName,
        CreateTime: Date.now(),
        MsgType: 'news',
        ArticleCount: newsContent.length,
        Articles: { ...ArticlesArr },
      },
    }
    return xml.jsonToXml(returnJson)
  }
  // 获取图文群发每日数据
  async getarticledata(ctx, summaryapi, beginDate, endDate) {
    const self = this;
    const rsAccess = await self.getAccessToken(summaryapi)
    if (!rsAccess.success) {
      return ctx.error('WX_ACCESSTOKEN_ERROR');
    }
    // 格式化请求连接
    const url = nodeutil.format(wxapis.apiURL[summaryapi], wxapis.apiDomain, rsAccess.access_token);
    const requestOpt = {
      url,
      method: 'POST',
      body: {
        begin_date: moment(beginDate).format('YYYY-MM-DD'),
        end_date: moment(endDate).format('YYYY-MM-DD'),
      },
    }
    const rs = await self.request(requestOpt);
    return rs
  }
  async createNonceStr(len) {
    let rsLength = 32;
    if (len && len !== 0) {
      rsLength = len
    }
    const $chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';
    let rsStr = '';
    const maxPos = $chars.length;
    for (let i = 0; i < rsLength; i += 1) {
      rsStr += $chars.charAt(Math.floor(Math.random() * maxPos));
    }
    return rsStr;
  }
  // 获取小程序码，适用于需要的码数量极多的业务场景。
  async getwxacodeunlimit(ctx, scene, page, path) {
    const self = this;
    const rsAccess = await self.getAccessToken('getwxacodeunlimit')
    if (!rsAccess.success) {
      return ctx.error('WX_ACCESSTOKEN_ERROR');
    }
    // 格式化请求连接
    const url = nodeutil.format(wxapis.apiURL.getwxacodeunlimit, wxapis.apiDomain, rsAccess.access_token);
    const requestOpt = {
      url,
      method: 'POST',
      responseType: 'arraybuffer',
      body: JSON.stringify({
        scene,
        page,
      }),
      is_hyaline: true,
    }
    const result = await rq(requestOpt).pipe(fs.createWriteStream(path));
    return result;
  }
  // 登录凭证校验
  async Authcode2Session(tokencode) {
    const that = this;
    // 格式化请求连接
    const url = nodeutil.format(wxapis.apiURL.authcode2Session, wxapis.apiDomain, that.appID, that.appSecret, tokencode, 'authorization_code');
    const requestOpt = { url }
    console.log('>>>>>>>>>>>>>>>>微信认证 Authcode2Session requestOpt : ', requestOpt);
    const rs = await that.request(requestOpt);
    console.log('>>>>>>>>>>>>>>>>微信认证 Authcode2Session result : ', rs);
    return rs;
  }
}

export default WeChat

export class wxmp {
  constructor(config) {
    // 设置 WeChat 对象属性 appID
    this.appID = config.appID;
    // 设置 WeChat 对象属性 appScrect
    this.appSecret = config.appSecret;
  }
  async request(options) {
    const that = this;
    const reqOpt = options;
    if (!reqOpt.url) {
      return
    }
    reqOpt.headers = { 'User-Agent': 'request' };
    reqOpt.json = true;
    reqOpt.token = that.token;
    if (!options.method) {
      reqOpt.method = 'GET'
    }
    return rq(reqOpt).then(parsedResult => parsedResult).catch((err) => {
      throw new Error(err)
    });
  }
  // 登录凭证校验
  async Authcode2Session(tokencode) {
    const that = this;
    // 格式化请求连接
    const url = nodeutil.format(wxapis.apiURL.authcode2Session, wxapis.apiDomain, that.appID, that.appSecret, tokencode, 'authorization_code');
    const requestOpt = { url }
    console.log('>>>>>>>>>>>>>>>>微信认证 Authcode2Session requestOpt : ', requestOpt);
    const rs = await that.request(requestOpt);
    console.log('>>>>>>>>>>>>>>>>微信认证 Authcode2Session result : ', rs);
    return rs;
  }
}

export class QyWeChat {
  constructor(config) {
    this.config = config;
    // 设置 WeChat 对象属性 appID
    this.corpid = config.corpid;
    // 设置 WeChat 对象属性 appScrect
    this.corpsecret = config.corpsecret;
  }
  async request(options) {
    const that = this;
    const reqOpt = options;
    if (!reqOpt.url) {
      return
    }
    reqOpt.headers = { 'User-Agent': 'request' };
    reqOpt.json = true;
    reqOpt.token = that.token;
    if (!options.method) {
      reqOpt.method = 'GET'
    }
    return rq(reqOpt).then(parsedResult => parsedResult).catch((err) => {
      throw new Error(err)
    });
  }
  async getAccessToken(callmethod) {
    if (callmethod) {
      console.log('getAccessToken callmethod:', callmethod);
    }
    const that = this;
    const rsAccess = {
      success: true,
      message: '',
      access_token: '',
    }
    const DBToken = await wxaccessDao.findOne({
      where: {
        access_type: 'access',
        expires_time: {
          [Sequelize.Op.gt]: moment().format('YYYY-MM-DD HH:mm:ss'),
        },
        type: 'qywx',
      },
    });
    if (DBToken && DBToken.access_token !== '') {
      rsAccess.access_token = DBToken.access_token
      return rsAccess
    }
    // 格式化请求地址
    const url = nodeutil.format(qywxapis.apiURL.accessTokenApi, qywxapis.apiDomain, that.corpid, that.corpsecret);
    console.log('>>>>>>>>>>>>>>>>>>> 格式化请求地址:', url);
    const rs = await that.request({ url });
    console.log('>>>>>>>>>>>>>>>>>>> 请求结果:', rs);
    if (rs.errcode) {
      rsAccess.success = false;
      rsAccess.message = rs.errmsg;
      return rsAccess
    }
    /* access_token的有效期通过返回的expires_in来传达，正常情况下为7200秒（2小时），有效期内重复获取返回相同结果，过期后获取会返回新的access_token */
    const expirestime = moment().add(1.8, 'hour').format('YYYY-MM-DD HH:mm:ss')
    const rssave = await wxaccessDao.create({
      access_type: 'access',
      access_token: rs.access_token,
      expires_time: expirestime,
      type: 'qywx',
    })
    if (!rssave) {
      rsAccess.success = false;
      rsAccess.message = 'DB save error';
      return rsAccess
    }
    rsAccess.access_token = rs.access_token
    // console.log('getAccessToken access_token', rsAccess)
    return rsAccess
  }
  // 登录凭证校验
  async Authcode2Session(tokencode, ctx) {
    const that = this;
    const rsAccess = await that.getAccessToken('Authcode2Session')
    if (!rsAccess.success) {
      return ctx.error('WX_ACCESSTOKENERROR');
    }
    // 格式化请求连接
    const url = nodeutil.format(qywxapis.apiURL.authcode2Session, qywxapis.apiDomain, rsAccess.access_token, tokencode, 'authorization_code');
    const requestOpt = { url }
    console.log('>>>>>>>>>>>>>>>>企业微信认证 Authcode2Session requestOpt : ', requestOpt);
    const rs = await that.request(requestOpt);
    console.log('>>>>>>>>>>>>>>>>企业微信认证 Authcode2Session result : ', rs);
    return rs;
  }
}
