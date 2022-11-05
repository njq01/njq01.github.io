---
title: Go语言开发项目后端
date: 2022-11-05 18:08:04
tags:
---
  关于go语言开发项目后端的实践
  <!-- more -->
作者 [陈新杰cxj](https://njq01.github.io/)
最近几天学习了go语言的后端项目开发并实践了一下，现在系统讲一下go语言运用gin框架和gorm框架实现开发。这是参考代码的[地址](https://github.com/njq01/goprojcet_example)
工具：goland，mysql  

<br/>
<br/>
<br/>

> # 1. 技术栈 & 名词解释
**[Gin](https://github.com/gin-gonic/gin)框架**: 一款轻量级, 高性能, 简单的Golang后端开发框架.

**[Gorm](https://gorm.io/zh_CN/)框架**:
> **ORM**: Object–Relational Mapping, 对象关系映射

对象就是Go中的`struct`, 关系就是MySQL中的各种表

**Viper**: 配置读取绑定

**MySQL**: 一款流行的关系型数据库
> **SQL**: Structure Query Language 结构化查询语言

MySQL 使用 SQL 作为查询语言.

**Git** 一款版本控制软件. 通过Git 可以记录项目代码的变化情况.
> GitHub 是 一个Git的远端管理平台, 可以在上面开源你的代码.

**Apifox** 一个管理API的工具, 可以方便的编写API文档, 进行测试等等.

> API: Application Programming Interface 应用编程接口, 一般也简称接口. 本文后端主要面向的就是RESTful API的编程

<br/>
<br/>
<br/>

> # 2. 框架
大致的文件分为五个文件夹和main.go作为主入口。
1. config文件   主要作用是设置各种配置，其中包括database的设置，sever端口的设置，jwt的设置，邮箱的配置
2. db文件   主要储存数据库表的模型，将其与json对应。并启动数据库服务
3. router文件   主要是路径的储存，对于每一个请求分配对应的处理器函数
4. controller文件   储存了处理函数，将处理器函数和对应的表进行处理
5. utility文件 主要存放了工具，将中间件和加密文件与函数储存

在进行所有项目之前，我们应该与前端确定**api文档**，这个是我们后端项目的基础，我们的传输应该以api文档为准。

> 下面给出一个接口的api样例

> ### 1. login接口
**路由接口**：`user/login`

**接口方法**：post

| 参数        | 类型 | 值   |
|-----------| --- |-----|
| user_name |string| 用户名 |
| password  |string | 密码  |

传入示例：
````json
{
    "user_name": "admin",
    "password": "1234"
}
````
返回值

|code| msg         |说明|
|----|-------------|---|
|200| ok          |操作成功，并返回user_id|
|404| User not found |用户找不到|
|400||连接错误|
|400|Wrong Password|密码错误|


返回示例：
```json
{
   "data": {
      "user_id": 1
   },
   "msg": "OK"
}

```
这就是api的书写

   <br />
    <br />

接下来将针对每一个文件进行说明

<br/>
<br/>
<br/>

   > # 3. config文件
   config文件在全局中起到了配置作用，他规定了我们服务器和数据库的端口及进入方式，相当于是声明了
   这里我们使用[yaml](https://github.com/yaml)和[viper](https://github.com/spf13/viper)进行配置，下面给出config.go和config.yaml的代码
   > 下面给出config.yaml的代码 
```yaml
 dev: true

server:
  port: "8888"
  allow_origins:
    - "http://localhost:3000"

db:
  user_name: "name"
  password: "pwd"
  address: "localhost:3306"
  db_name: "db_name"

jwt:
  secret: "secretKey"
  issuer: "issuer"
  expires: 48 

  email:
  sender: "email@qq.com"
  pwd:  "************"
  smtpaddr: "smtp.qq.com"
  smtpport: "465"
  ```
  > 下面给出config.go的代码

```go
package config

import (
	"log"

	"github.com/spf13/viper"
)

type server struct {
	Port         string   `mapstructure:"port"`
	AllowOrigins []string `mapstructure:"allow_origins"`
}
type db struct {
	UserName string `mapstructure:"user_name"`
	Password string `mapstructure:"password"`
	Address  string `mapstructure:"address"`
	DBName   string `mapstructure:"db_name"`
}
type jwt struct {
	Secret  string `mapstructure:"secret"`
	Expires uint   `mapstructure:"expires"`
	Issuer  string `mapstructure:"issuer"`
}
type email struct {
	Sender   string `mapstructure:"sender"`
	Pwd      string `mapstructure:"pwd"`
	SmtpAddr string `mapstructure:"smtpaddr"`
	SmtpPort int    `mapstructure:"smtpport"`
}
type config struct {
	Dev    bool   `mapstructure:"dev"`
	Server server `mapstructure:"server"`
	DB     db     `mapstructure:"db"`
	Jwt    jwt    `mapstructure:"jwt"`
    Email  email  `mapstructure:"email"`
}

var Config config

func InitConfig() {
	var config = viper.New()
	config.SetConfigName("config")
	config.SetConfigType("yaml")
	config.AddConfigPath("./config")
	err := config.ReadInConfig()
	if err != nil {
		log.Panicln("Config Error: ", err)
	}
	config.Unmarshal(&Config)
}
```
这两个文件主要描述了项目的配置，可以看出这是项目的基础
只需要在主函数中调用```InitConfig()```即可

<br/>
<br/>
<br/>

> # 4.  db和model的初始化
在完成配置文件后，我们要开始初始化数据库和数据库模型。这里我们使用**[Gorm](https://gorm.io/zh_CN/)框架**来对mysql数据库进行操作。

> ## 4.1 初始化数据库

```go
package db

import (
	"fmt"
	"log"

	"test/config"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func InitDB() {
	dsn := fmt.Sprintf("%v:%v@tcp(%v)/%v?charset=utf8mb4&parseTime=True&loc=Local",
		config.Config.DB.UserName,
		config.Config.DB.Password,
		config.Config.DB.Address,
		config.Config.DB.DBName,
	)
	var err error
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		log.Panicln("Database Error: ", err)
	} else {
		fmt.Printf("database start")
	}
}
```
这样就可以完成数据库的初始化

下面我们进行数据表的初始化

<br/>
<br/>

> ## 4.2  设置项目中的数据库模型

我们对前端发来的json等请求和对数据库进行操作，主要是依靠建立模型进行绑定和交互,而模型在go里面主要是struct结构体。例如user表的模型如下：

```go
type User struct {
	UserId   int    `json:"user_id"`
	UserName string `json:"user_name"`
	Email    string `json:"user_email"`
	Password string `json:"password"`
	Usersex  string `json:"user_sex"`
}
```
注意三点：

1. 这里的```json:"user_id```是对json格式进行绑定，当我们通过路由绑定接收到前端传来的json数据时，我们可以自动将json对象的值进行读取，并保存到相应的struct的变量中

2. 关于UserId的问题。当我们将一个struct的变量命名为对应数据表的表名+Id时，表会默认这个字段值是自动编号，无需我们手动输入，这是gorm的特点，但是前提是命名规范满足驼峰命名法

3. 关于大小写的问题，我们在struct新建字段时在开头第一个必须大写，不然就是对数据表隐藏我们的字段，在刚开始加载时，就不会在mysql数据库中新建出这个字段

注意，模型应当与数据表对应，每一个模型都是数据表在go项目中的体现。

<br/>
<br/>

> ## 4.3 初始化数据表

初始化数据库主要是在项目刚跑在服务器上时，将mysql中的数据表和模型进行绑定，并在mysql中建立相应的数据表。代码如下：

```go
package model

import (
	"log"
	"test/db"
)

func InitModel() {
	ok := db.DB.AutoMigrate(&User{}, &Resume{})
	if ok != nil {
		log.Panicln("Database Error: ", ok)
	}
}
```
这里完成了对user表和resume表的新建，注意·***automigrate***方法是在数据库中新建数据表，假如数据库中已经有了对应的表，方法不会执行和覆盖。

<br/>
<br/>

> ## 4.4 对数据库的CRUD操作

所谓的**CRUD**就是指插入，更新，查找和删除。我们这里调用**[Gorm](https://gorm.io/zh_CN/)中的方法来简便对数据库的操作

<br/>

> ### 4.4.1 创建记录

#### 创建记录

```go
user := User{Name: "Jinzhu", Age: 18, Birthday: time.Now()}
result := db.Create(&user) // 通过数据的指针来创建
user.ID             // 返回插入数据的主键
result.Error        // 返回 error
result.RowsAffected // 返回插入记录的条数
```

#### 用指定的字段创建记录

创建记录并更新给出的字段。

```go
db.Select("Name", "Age", "CreatedAt").Create(&user)
// INSERT INTO `users` (`name`,`age`,`created_at`) VALUES ("jinzhu", 18, "2020-07-04 11:05:21.775")
```

<br/>

> ### 4.4.2 查找记录

GORM 提供了`First`、`Take`、`Last` 方法，以便从数据库中检索单个对象。当查询数据库时它添加了` LIMIT 1` 条件，且没有找到记录时，它会返回 `ErrRecordNotFound `错误

```go
// 获取第一条记录（主键升序）
db.First(&user)
// SELECT * FROM users ORDER BY id LIMIT 1;

// 获取一条记录，没有指定排序字段
db.Take(&user)
// SELECT * FROM users LIMIT 1;

// 获取最后一条记录（主键降序）
db.Last(&user)
// SELECT * FROM users ORDER BY id DESC LIMIT 1;

result := db.First(&user)
result.RowsAffected // 返回找到的记录数
result.Error        // returns error or nil

// 检查 ErrRecordNotFound 错误
errors.Is(result.Error, gorm.ErrRecordNotFound)
```
也可以使用Find，比如db.Limit(1).Find(&user)，Find方法可以接受struct和slice的数据。
```go
var user User
var users []User

// works because destination struct is passed in
db.First(&user)
// SELECT * FROM `users` ORDER BY `users`.`id` LIMIT 1

// works because model is specified using `db.Model()`
result := map[string]interface{}{}
db.Model(&User{}).First(&result)
// SELECT * FROM `users` ORDER BY `users`.`id` LIMIT 1

// doesn't work
result := map[string]interface{}{}
db.Table("users").First(&result)

// works with Take
result := map[string]interface{}{}
db.Table("users").Take(&result)

// no primary key defined, results will be ordered by first field (i.e., `Code`)
type Language struct {
  Code string
  Name string
}
db.First(&Language{})
// SELECT * FROM `languages` ORDER BY `languages`.`code` LIMIT 1
```

再老的版本中也可以写为`db.DB.Where("title = ? AND userid = ?", resume_name, userid).First(&user)`

<br/>

####  内联条件

查询条件也可以被内联到 First 和 Find 之类的方法中，其用法类似于 Where。
```go
// Get by primary key if it were a non-integer type
db.First(&user, "id = ?", "string_primary_key")
// SELECT * FROM users WHERE id = 'string_primary_key';

// Plain SQL
db.Find(&user, "name = ?", "jinzhu")
// SELECT * FROM users WHERE name = "jinzhu";

db.Find(&users, "name <> ? AND age > ?", "jinzhu", 20)
// SELECT * FROM users WHERE name <> "jinzhu" AND age > 20;

// Struct
db.Find(&users, User{Age: 20})
// SELECT * FROM users WHERE age = 20;

// Map
db.Find(&users, map[string]interface{}{"age": 20})
// SELECT * FROM users WHERE age = 20;
```

<br/>

#### not条件
```go
db.Not("name = ?", "jinzhu").First(&user)
// SELECT * FROM users WHERE NOT name = "jinzhu" ORDER BY id LIMIT 1;

// Not In
db.Not(map[string]interface{}{"name": []string{"jinzhu", "jinzhu 2"}}).Find(&users)
// SELECT * FROM users WHERE name NOT IN ("jinzhu", "jinzhu 2");

// Struct
db.Not(User{Name: "jinzhu", Age: 18}).First(&user)
// SELECT * FROM users WHERE name <> "jinzhu" AND age <> 18 ORDER BY id LIMIT 1;

// Not In slice of primary keys
db.Not([]int64{1,2,3}).First(&user)
// SELECT * FROM users WHERE id NOT IN (1,2,3) ORDER BY id LIMIT 1;
```

<br/>

#### or条件

```go
db.Where("role = ?", "admin").Or("role = ?", "super_admin").Find(&users)
// SELECT * FROM users WHERE role = 'admin' OR role = 'super_admin';

// Struct
db.Where("name = 'jinzhu'").Or(User{Name: "jinzhu 2", Age: 18}).Find(&users)
// SELECT * FROM users WHERE name = 'jinzhu' OR (name = 'jinzhu 2' AND age = 18);

// Map
db.Where("name = 'jinzhu'").Or(map[string]interface{}{"name": "jinzhu 2", "age": 18}).Find(&users)
// SELECT * FROM users WHERE name = 'jinzhu' OR (name = 'jinzhu 2' AND age = 18);
```

<br/>

> ### 4.4.3 高级查询

#### 智能选择字段
GORM 允许通过 `Select` 方法选择特定的字段，如果您在应用程序中经常使用此功能，你也可以定义一个较小的结构体，以实现调用 API 时自动选择特定的字段，例如：
```go
type User struct {
  ID     uint
  Name   string
  Age    int
  Gender string
  // 假设后面还有几百个字段...
}

type APIUser struct {
  ID   uint
  Name string
}

// 查询时会自动选择 `id`, `name` 字段
db.Model(&User{}).Limit(10).Find(&APIUser{})
// SELECT `id`, `name` FROM `users` LIMIT 10
```

再比如：
```go
func Getresumes(userid int) ([]Resume, error) {
	var resumes []Resume
	result := db.DB.Where(
		Resume{
			Userid: userid,
		}).Find(&resumes)
	if result.Error != nil {
		return nil, result.Error
	}

	return resumes, nil
}
```

<br/>

> ### 4.4.4 更新

<br/>

#### 保存所有字段

`Save` 会保存所有的字段，即使字段是零值

```go
db.First(&user)

user.Name = "jinzhu 2"
user.Age = 100
db.Save(&user)
// UPDATE users SET name='jinzhu 2', age=100, birthday='2016-01-01', updated_at = '2013-11-17 21:34:10' WHERE id=111;
```

<br/>

#### 更新单个列

当使用 `Update` 更新单个列时，你需要指定条件，否则会返回 `ErrMissingWhereClause` 错误，查看 Block Global Updates 获取详情。当使用了 `Model  ` 方法，且该对象主键有值，该值会被用于构建条件，例如：

```go
// 条件更新
db.Model(&User{}).Where("active = ?", true).Update("name", "hello")
// UPDATE users SET name='hello', updated_at='2013-11-17 21:34:10' WHERE active=true;

// User 的 ID 是 `111`
db.Model(&user).Update("name", "hello")
// UPDATE users SET name='hello', updated_at='2013-11-17 21:34:10' WHERE id=111;

// 根据条件和 model 的值进行更新
db.Model(&user).Where("active = ?", true).Update("name", "hello")
// UPDATE users SET name='hello', updated_at='2013-11-17 21:34:10' WHERE id=111 AND active=true;
```

<br/>

> ### 4.4.5 删除

#### 删除一条记录

删除一条记录时，删除对象需要指定主键，否则会触发 批量 Delete，例如：

```go
// Email 的 ID 是 `10`
db.Delete(&email)
// DELETE from emails where id = 10;

// 带额外条件的删除
db.Where("name = ?", "jinzhu").Delete(&email)
// DELETE from emails where id = 10 AND name = "jinzhu";
```

<br/>

#### 根据主键删除
GORM 允许通过主键(可以是复合主键)和内联条件来删除对象，它可以使用数字（如以下例子。也可以使用字符串——译者注）。查看 查询-内联条件（Query Inline Conditions） 了解详情。

```go
db.Delete(&User{}, 10)
// DELETE FROM users WHERE id = 10;

db.Delete(&User{}, "10")
// DELETE FROM users WHERE id = 10;

db.Delete(&users, []int{1,2,3})
// DELETE FROM users WHERE id IN (1,2,3);
```

<br/>

#### 批量删除
如果指定的值不包括主属性，那么 GORM 会执行批量删除，它将删除所有匹配的记录

```go
db.Where("email LIKE ?", "%jinzhu%").Delete(&Email{})
// DELETE from emails where email LIKE "%jinzhu%";

db.Delete(&Email{}, "email LIKE ?", "%jinzhu%")
// DELETE from emails where email LIKE "%jinzhu%";
```
<br/>
<br/>
<br/>

> # 5.  utility工具的封装

我们先写一些工具，方便我们之后的使用。其中包括：***时间处理**、***token处理**、**密码加密**、**http请求发送**

<br/>
<br/>

> ## 5.1  时间处理

```go
package utility

import (
	"gorm.io/gorm/utils"
	"time"
)

func GetData() string {
	now := time.Now()
	year := utils.ToString(now.Year())
	month := now.Format("01")
	day := utils.ToString(now.Format("02"))
	return year + "_" + month + "_" + day
}
```
我们可以通过调用```GetData()```方法来实现读取本地时间并且格式化。

<br/>
<br/>

> ## 5.2 response工具

```go
package utility

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Response(code int, msg string, data gin.H, c *gin.Context) {
	if data != nil {
		c.JSON(code, gin.H{
			"msg":  msg,
			"data": data,
		})
	} else {
		c.JSON(code, gin.H{
			"msg": msg,
		})
	}
}

func ResponseBadRequest(c *gin.Context) {
	Response(http.StatusBadRequest, "Bad request", nil, c)
}

func ResponseInternalServerError(c *gin.Context) {
	Response(http.StatusInternalServerError, "Internal server error", nil, c)
}

func ResponseOK(c *gin.Context, data gin.H) {
	Response(http.StatusOK, "OK", data, c)
}
```
我们这里封装了四个工具，注意在gin框架下，我们给前端发送http请求并返回json数据主要是依靠调用**gin.Context**下的`Json()` 方法来实现。其中的***Gin.H**是规定返回的结构体，将数据封装在结构体中，以此传输。这里总共有四个http工具，**Response()**是对发送简单http请求进行了封装，我们可以调用此方法来发送指定的msg，code码，和其他数据。**ResponseBadRequest()**是表示前端传来的数据有问题，我们返回一个code码**400**。**ResponseInternalServerError()**是表示网络有问题，我们返回一个code码**500**。**ResponseOK()**是表示返回成功，我们返回一个code码**200**。

<br/>
<br/>

> ## 5.3 密码对称性加密
```go
package utility

import "golang.org/x/crypto/bcrypt"

func PasswordHash(pwd string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func PasswordVerify(pwd, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pwd))
	return err == nil
}
```
这里主要是用到了**crypto**库，而`PasswordHash()`是对密码进行对称性加密，`PasswordVerify()`是对密码进行对比验证。

<br/>
<br/>

> ## 5.4 token的使用和处理

我们使用token来对前后端的数据传输进行加密，token相当于是一个身份令牌，前端通过token来进行标识用户，请求相应的后端服务。

> 下面给出token的生成方法：

```go
package utility

import (
	"log"
	"resume/config"
	"time"

	"github.com/golang-jwt/jwt"
)

type JwtData struct {
	ID string `json:"id"`
	jwt.StandardClaims
}

func GenerateStandardJwt(jwtData *JwtData) string {
	claims := jwtData
	claims.StandardClaims = jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Duration(time.Duration(config.Config.Jwt.Expires) * time.Hour)).Unix(),
		Issuer:    config.Config.Jwt.Issuer,
	}
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tokenClaims.SignedString([]byte(config.Config.Jwt.Secret))
	if err != nil {
		log.Fatalln("Jwt Error", err)
		panic(err)
	}
	return token
}

func ParseToken(token string) (string, error) {
	jwtSecret := []byte(config.Config.Jwt.Secret)
	tokenClaims, err := jwt.ParseWithClaims(token, &JwtData{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if tokenClaims != nil {
		if claims, ok := tokenClaims.Claims.(*JwtData); ok && tokenClaims.Valid {
			return claims.ID, err
		}
	}
	return "", err
}
```
我们这里通过对指定的字段值进行加密，并生成一个字符串，这个字符串唯一，这里主要用到了**jwt**库，` ParseToken()`完成了对指定值的处理。前端在请求我们的数据时，应当将token放在http请求头中，我们对请求头进行处理和判断，并操作相应的服务。
> 下面写一个中间件来处理，路由接受到http请求时，对http请求头中的token进行一个处理和判断
```go
package middleware

import (
	"log"
	"net/http"
	"resume/utility"
	"strconv"

	"github.com/gin-gonic/gin"
)

func Authorization(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		utility.Response(http.StatusUnauthorized, "No Token", nil, c)
		c.Abort()
		return
	}
	id, err := utility.ParseToken(token)
	if err != nil {
		utility.Response(http.StatusUnauthorized, "Bad Token", nil, c)
		c.Abort()
		return
	}
	id_int, ok := strconv.Atoi(id)
	if ok != nil {
		utility.Response(http.StatusInternalServerError, "Internal server error", nil, c)
		log.Println(ok)
		c.Abort()
	}
	c.Set("user_id", id_int)
	c.Next()
}
```
因为在我们的逻辑中，userid是作为主键，是唯一的。因此，userid也就作为了token生成的依据。我们这个方法会在处理函数之前调用，来判断这个请求的合法性。例如，我们在路由中，应该写为`	Router.GET("/api/user", middleware.Authorization, controller.GetUserInfo)`这样子。

<br/>
<br/>
<br/>

> # 5.Router的处理

Router的作用是绑定api路由，前端将请求发到指定的路由上，分配具体的处理函数进行处理。
> 下面给出设置对应路由的方法
```go
package router

import (
	"test/controller"
	"test/utility/middleware"
)

func SetRouter() {
	Router.POST("/api/user/register", controller.Register)
	Router.POST("/api/class", middleware.Authorization, controller.AddClass)
	Router.GET("/api/class", middleware.Authorization, controller.GetClasses)
}
```
注意`Router.GET("/api/class", middleware.Authorization, controller.GetClasses)`其中的`middleware.Authorization`是调用了工具中的token处理方法，判断token符不符合我们的要求。如果不符合则不会调用相应的处理函数

> 下面给出设置路由的代码
```go
package router

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"test/config"
)

var Router *gin.Engine

func InitRouter() {
	Router = gin.Default()
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowHeaders = append(corsConfig.AllowHeaders, "Authorization")
	if config.Config.Dev {
		corsConfig.AllowAllOrigins = true
	} else {
		corsConfig.AllowOrigins = config.Config.Server.AllowOrigins
	}
	Router.Use(cors.New(corsConfig))
	SetRouter()
}
```
这里设置了路由的基本参数

在**main.go**主函数中，我们只需要添加以下代码即可
```go
router.InitRouter()
router.Router.Run(":" + config.Config.Server.Port)
 ```
这样就启动了在yaml中规定好的端口的服务器

<br/>
<br/>
<br/>

> # 6. 处理函数controller的编写

处理函数是对指定路由接受到前端发来的请求时做出的处理和响应。这里以user表中的`Register()`函数作为例子。

```go
func Register(c *gin.Context) {
	var data model.User
	err := c.ShouldBindJSON(&data)
	if err != nil {
		log.Println(err)
		utility.ResponseBadRequest(c)
		return
	}
	_, err = model.GetUserByUsername(data.UserName)
	if err == nil {
		log.Println(err)
		utility.Response(404, "username repeat", nil, c)
		return
	}
	data.Password, err = utility.PasswordHash(data.Password)
	if err != nil {
		log.Println(err)
		utility.ResponseInternalServerError(c)
		return
	}
	var last model.User
	db.DB.Last(&last)
	data.Userid = last.Userid + 1
	err = model.AddUser(&data)
	if err != nil {
		log.Println(err)
		utility.ResponseInternalServerError(c)
		return
	}
	utility.Response(http.StatusOK, "OK", nil, c)
}
```
在**gin**框架下，我们可以通过` c.ShouldBindJSON(&data)`来进行绑定，从而获得前端发来的请求中的json数据，并且储存在data变量中。我们**处理函数**的主要功能便是接受前端发来的请求，进行对应的处理，这是我们业务的核心所在。

<br/>
<br/>
<br/>

> # 7. main.go的编写

main.go相当于是项目的入口，我们通过命令`go run main.go`来使项目运行。编写main.go是项目的最后一步了。

> 下面给出main.go的代码

```go
package main

import (
	"test/config"
	"test/db"
	"test/db/model"
	"test/router"
)

func main() {
	config.InitConfig()
	db.InitDB()
	model.InitModel()
	router.InitRouter()
	router.Router.Run(":" + config.Config.Server.Port)
}
```
<br/>
<br/>
<br/>

## 这就完成了一个简单的gin项目了,之后要做的便是上传到云服务器了。

 ####  注意，本文这里是直接应用了大量文档中的样例，以保证准确性，建议读者自行阅读**[Gorm]>(https://gorm.io/zh_CN/)文档**和：**[Gin](https://github.com/gin-gonic/gin)文档**，里面有更多的高级用法和准确描述。

参考文档：**[Gin](https://github.com/gin-gonic/gin)文档**、**[Gorm](https://gorm.io/zh_CN/)文档**。











