# PHP-IDPS

这是一个基于php的Web入侵检测与防御系统



##### 目录结构:

- ​    waf.php     ==> waf文件，导入防护页面即可 
- ​    waf.rules   ==> 规则文件，用户可自定义规则
- ​    waf.log     ==> 日志文件
- ​    count.txt   ==> 计数文件，系统自动调用
- ​    README.txt  ==> 帮助文档

##### Linux系统:

```
修改 /etc/sudoers 文件，添加以下以下格式的行: 
	daemon  ALL=(ALL)        NOPASSWD: ALL

上述命令行表示给对应的web服务用户添加防火墙执行权限

给日志文件、计数文件添加其他用户读写的权限
```

##### 规则格式:

```
规则编号 规则说明 执行动作 (具体的规则内容;....)
```

##### 规则示例:

```
wid:100;msg:规则说明;alert (http_method:/GET/;http_stat_code:/404/;count:2;target:src_ip;time:1)

以上规则表示匹配在10秒钟之内的源ip相同且响应状态码为404的2次GET请求，并记录告警日志。
```

##### 规则详情:

    wid                     规则编号
    msg                     规则说明
    规则的执行动作:  alert    告警动作，记录日志
                   drop     封禁动作，用于封禁源ip，需搭配firewalld防火墙使用
            
    支持的过滤内容:
        request_uri         HTTP客户端请求的URI内容
        http_stat_code      服务器响应的HTTP状态字段内容
        http_method         客户端使用的HTTP方法（GET，POST等）
        http_header         HTTP请求头的所有内容
        http_cookie         HTTP头字段的Cookie内容
        http_client_body    HTTP客户端请求的主体内容,如POST请求正文
        user_agent          用户代理
        referer             HTTP来源地址，用来表示从哪儿链接到目前的网页
    
        上述过滤内容后面必须跟正则表达式，格式 => 过滤内容:正则表达式
    
    其它条件:
        count               匹配成功过滤的命中次数，满足次数后执行动作，且一条规则中只能存在一个count
        time                指定在一定时间内满足过滤规则即执行动作，以秒为单位。
        target              前置条件为 count 或 time; 匹配指定源或目标的信息,格式:[src_ip|dest_ip]，且一条规则中只能存在一个target
        dest_ip             接收请求的目标ip
        src_ip              发送请求的源ip

##### 注意事项:

1. ​    如果规则的 wid 相同，则前面的规则会被后面的规则覆盖
2. ​    如果同一条规则中存在相同的过滤条件，则前面过滤条件会被后面的同名条件覆盖
3. ​    规则的 : 和 ; 两边不能出现空格
4. ​    每一条规则必须存在一个过滤内容，其他条件不是必须的
