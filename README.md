# SpringSecurityOoauth

Nesse repositório serão abordados os seguintes assuntos:

* Entenda os conceitos básicos de autenticação, autorização e proteção de aplicativos da web
* Identificar e avaliar opções de autenticação e autorização
* Proteja uma API REST usando o suporte do servidor de recursos OAuth 2.0 do Spring Security
* Endpoints Spring MVC seguros e consultas Spring Data usando primitivas Spring Security
* Teste seu aplicativo com a segurança habilitada

# A API Rest sem segurança
Clone a aplicação desse repositório, em seguida, inicie-a.
Talvez seja necessário fazer checkout para o commit inicial da aplicação:
```
git checkout 2ef5144
```
Em seguinda, utilizando uma ferramenta para requisições Http (Como Postman, HTTPie, ou outra de sua preferência), faça uma requisição conforme segue:
``` bash
GET http://localhost:8080/cashcards
```

Requisições do tipo GET, em aplicações não seguras, ou seja, onde o cabeçalho da requisição, não requer dados de autenticação, também podem ser feitas através de seu navegador:

![image](https://github.com/user-attachments/assets/c97d1337-6a94-4736-9403-f37ff8419a56)

## Os potencias risco e fragilidades de uma aplicação não segura
Negligenciar a segurança dos endpoints da nossa API tem pelo menos três consequências:

- O conteúdo é *público* – você não pode controlar quem vê as informações
- O conteúdo é *anônimo* – você não pode saber quem está perguntando
- O conteúdo está *desprotegido* - agentes mal-intencionados podem tirar vantagem das vulnerabilidades baseadas no navegador

**Conteúdo Público**
Como o conteúdo é público, qualquer usuário com acesso ao local da rede pode comandar a API e ver os dados. Embora isso possa ser um suavizado com a segurança da rede, na prática, a maioria das APIs REST são frequentemente expostas à Internet pública por meio de navegadores ou gateways de API. Mesmo que não tenham sido expostos à Internet pública, a ameaça real de server-side request forgery (SSRF) deveria nos fazer pensar se estivermos pensando em deixar qualquer uma de nossas APIs de produção abertas dessa forma.

**Conteúdo anônimo**
Como o conteúdo é anônimo, não podemos decidir se o usuário é conhecido, confiável e autorizado. Na prática, também é mais complicado mostrar o conteúdo específico do usuário porque seu identificador não está em nenhum conteúdo da solicitação.

Você acabou de ver esse ponto em ação quando consultou a API pela primeira vez. Mostra o conteúdo dos usuários Sarah e Esuez5; é algo indesejado, do ponto de vista de produção. Mas! Isso pode ser corrigido exigindo autenticação.

**Conteúdo desprotegido**
E como o conteúdo está desprotegido, quando essa API REST é exposta a um navegador, ela pode tornar o aplicativo como um todo vulnerável a CSRF, MITM, XSS e outros ataques sem intervenção adicional.

## Sobre o erro 404s

Para compreensão, com a aplicação rodando, tente fazer uma requisição, em um endpoint que não existe:

``` bash
GET http://localhost:8080/endpoint-nao-existente
```
Um erro 404 será retornado, visto que o endpoint acessado não existe em nossa aplicação.

``` json
{
  "timestamp": "2024-08-08T15:19:19.017+00:00",
  "status": 404,
  "error": "Not Found",
  "path": "/endpoint-nao-existente"
}
```

Esse tipo de resposta, pode acabar servindo como pista, para alguém mal intecionado. Essa é uma vulnerabilidade. Vamos aprofundar mais sobre esses comportamentos enquanto implmentamos a segurança a nossa API.
Aqui estão algumas fontes, para pesquisa de vulnerabilidades: [Fingerprint](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server), [Directory Transversal](https://owasp.org/www-community/attacks/Path_Traversal) e [WSTG]([https://owasp.org/www-community/attacks/Path_Traversal](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account))

# Tornando nossa API Segura
## Segurança padrão (Secure Defaults)
Veremos asseguir alguns padrões do Spring Security e como sobre o princípio de *Segurança por padrão" e "Princípio do menor Privilégio" aos seus aplicativos.

*Secure by Default" ou *Seguro por Padrão*, é um princípio que incentiva você a garantir que suas configurações padrão sejam seguras. Dessa forma, se um aplicativo se encontrar em produção com os padrões de segurança, acaba não sendo vulnerável, por assim dizer.

*O Princípio do Menor Privilégio* é um princípio que incentiva você a pensar em cada fração de dado como um privilégio a ser possuído e a dar aos usuários finais os menores privilégios possíveis para que eles possam fazer bem seu trabalho.

O Spring Security adota ambas as filosofias para proteger automaticamente APIs REST. 

## Padrões de segurança do Spring

Quando o Spring Security está no classpath, o Spring Boot trabalha para configurar seu aplicativo com os seguintes padrões para uma API REST:

- Requer autenticação para todas as solicitações
- Responde com cabeçalhos seguros para todas as solicitações
- Requer mitigação de CSRF para todas as solicitações com efeitos colaterais
- Permite autenticação HTTP Basic com um usuário padrão
- Responde RESTfully a falhas de segurança
- Protege contra solicitações maliciosas com um firewall de aplicativo

Vamos analisar cada um deles de cada vez e relacioná-los aos princípios de Segurança por Padrão e Princípio do Menor Privilégio.

### Requer autenticação para todas as solicitações
Não importa se o endpoint é gerado por você ou pelo Boot, todas as requests em todos os dispatches exigem autenticação.

Independentemente da natureza do endpoint, o Spring Security aplica um Filtro de Servlet que inspeciona cada solicitação e a rejeita se a solicitação não for autenticada.

Este é um dos padrões de segurança do Spring Security.

*Servlets, (Filtros) Filters, and Dispatchers* 

Para entender um pouco melhor, precisamos abordar um pouco da terminologia da API do Servlet.

A API Java Servlet é responsável processar solicitações HTTP dentro de um aplicativo. Usando a terminologia de servlet, uma determinada solicitação HTTP pode passar por vários *dispatches*. Cada dispatch pode ser interceptado por vários *filtros* em seu caminho para um único *servlet*.

Um *servlet* manipula solicitações HTTP e produz uma resposta HTTP. Você fazer a analogia de um *servlet* como um "mini-servidor".

Um *filtro* intercepta requisições HTTP para lidar com preocupações transversais. Normalmente, os filtros enriquecem a requisição de alguma forma ou negam a requisição, impedindo que ela alcance o servlet.

Um *dispach* representa uma única passagem que uma solicitação HTTP faz por um conjunto de filtros e seu servlet de destino. Normalmente, uma solicitação HTTP passa primeiro pelo REQUEST dispatch (despacho), mas também pode passar posteriormente pelo ERROR dispatch, pelo FORWARD dispatch e outros.

Em termos de Spring, o Spring MVC constitui um único servlet, o Spring Security constitui um conjunto de filtros e o Spring Boot é fornecido com um contêiner incorporado que executa os vários *dispatchs* necessários para atender a uma única solicitação.

Tudo isso significa que os padrões do Spring Security exigem que cada *dispatch* seja autenticado.

### Benefícios de segurança
O legal desse arranjo é que não importa quem criou o endpoint. Se for você, Boot ou um terceiro, o filtro de servlet do Spring Security intercepta a solicitação antes que qualquer servlet (um "mini-servidor") possa processá-la.

Isso significa que quando você inclui o Spring Security, mesmo endpoints inexistentes retornarão um código 401 Unauthorized de status de resposta HTTP em vez de, digamos, um 404 Not Found, sendo o 404 resposta padrão do Spring Boot para endpoints inexistentes. O motivo dessa política rigorosa é por causa do *Princípio do Menor Privilégio*. Esse princípio diz que você deve oferecer apenas as informações que o usuário final tem o privilégio de saber.

Qual é o problema? O que há de tão privilegiado em um ponto final inexistente?

Para fins de segurança, até mesmo quais URIs são válidos são informações privilegiadas. Você pode imaginar se alguém solicitasse index.jsp ou /admin . Se o Spring Security retornasse um *404* nesses casos em vez de um *401*, isso significaria *404* que é uma dica para um agente mal-intencionado de que um determinado endpoint existe! O agente mal-intencionado pode usar essa dica para enumerar os URIs válidos das APIs REST, descobrir tecnologias vulneráveis ​​subjacentes e acelerar seu ataque.

### Responde com cabeçalhos seguros para todas as *requests*
Os cabeçalhos HTTP permitem que um cliente e um servidor troquem informações adicionais entre si em uma *request* e *response* HTTP. Seja uma solicitação autenticada ou não, o Spring Security sempre responde com determinados cabeçalhos por padrão. Cada cabeçalho assume como padrão o valor mais seguro disponível.

*Cabeçalhos de cache*
O primeiro são os cabeçalhos de controle de cache. Uma classe de vulnerabilidades baseadas em navegador é que as respostas HTTP são armazenadas em cache no navegador. Por exemplo, suponha que sua API REST retornou o seguinte:
``` json
[
  {
    "amount": 123.45,
    "id": 99,
    "owner": "sarah1"
  },
  {
    "amount": 1.0,
    "id": 100,
    "owner": "sarah1"
  }
]
```

Então essa *response* poderia ser armazenada em cache no navegador para recuperação posterior por um agente mal-intencionado na máquina local do usuário.

O Spring Security aplica configurações seguras para *Cache-Control* e outros cabeçalhos para mitigar essa vulnerabilidade.

***O Cabeçalho Strict Transport Security***
O segundo é o cabeçalho Strict Transport Security. Esse cabeçalho força um navegador a atualizar solicitações para HTTPS por um período de tempo especificado.

OBSERVAÇÃO: Como isso é destinado a *requests* HTTPS, ele não é escrito por padrão para uma *request* HTTP. Considerando isso, você pode não vê-lo em seus testes locais sobre HTTP.

Há muito tempo o HTTPS tem se mostrado um componente crítico de implantações seguras. Ataques man-in-the-middle tornam possível que os dados que passam entre o usuário final e a API REST sejam visualizados e modificados.

Tais ataques são mitigados por HTTPS, e o cabeçalho Strict Transport Security informa ao navegador para não enviar nenhuma solicitação para esta REST API por HTTP. Em vez disso, qualquer solicitação HTTP deve ser automaticamente atualizada pelo navegador para HTTPS.

**Opções de tipo de conteúdo**
O terceiro e último cabeçalho sobre o qual falaremos neste ponto é o cabeçalho X-Content-Type-Options. Este cabeçalho diz aos navegadores para não tentarem adivinhar o tipo de conteúdo de uma resposta.

Um lugar comum onde atores mal-intencionados se escondem é onde o protocolo HTTP é confuso e os aplicativos tentam entender, e adivinhar a intenção da *request* ou *response*. Um navegador, por exemplo, pode olhar para uma resposta que começa com <html> e tentar adivinhar que o tipo de conteúdo é text/html– ou seja, uma página da web. Às vezes, essa suposição não é segura. Por exemplo, é possível que uma imagem contenha conteúdo de script e o navegador pode ser enganado para adivinhar e executar steal-my-password.jpgccomo JavaScript.

O Spring Security resolve isso emitindo uma configuração segura *X-Content-Type-Options* por padrão.

###  Requer mitigação de CSRF para todas as solicitações com efeitos colaterais
Outro ponto em que as APIs REST correm risco é a capacidade de sites de terceiros fazerem solicitações a elas sem o consentimento do usuário.

Isso é possível porque os navegadores, por padrão, enviam todos os cookies e detalhes de autenticação HTTP Basic automaticamente para qualquer endpoint não XHR.

Por exemplo, dê uma olhada nesta *request* de uma suposta imagem:
´´´ html
<img src="https://mybank.example.org/account/32?transfer=25&toAccount=45" />
´´´
Essa solicitação será executada pelo navegador. Isso funciona porque o navegador não tem como saber se a URL aponta para uma imagem até que a resposta retorne. A essa altura, o dano já foi feito.

Como você pode imaginar, os navegadores até fazem essa solicitação em sites de terceiros. Os navegadores, por padrão, enviarão todos os cookies do *mybank.example.org*  e credenciais HTTP Basic para ele também por padrão. Isso significa que, se seu usuário estiver logado, um aplicativo de terceiros pode comandar sua API REST sem proteção adicional.

Por isso, o Spring Security protege automaticamente esses endpoints com efeitos colaterais, como POSTs, PUTs e DELETEs. Ele faz isso enviando um token especial para o cliente que ele deve usar em solicitações subsequentes. O token é transmitido de tal forma que terceiros não podem vê-lo. Então, quando o token é retornado, o Spring Security acredita que ele é legitimamente do cliente.

### Permite autenticação básica HTTP com um usuário padrão
O Spring Security gera um usuário padrão chamado user. Sua senha é gerada, no entanto, em cada inicialização.

O motivo para isso é que, se você acidentalmente implantar os padrões do Spring Security para produção, ninguém poderá usar o nome de usuário e a senha padrão para comandar seu aplicativo. Esta é outra instância clássica de criação de um aplicativo que é *Secure By Default* ou, um aplicativo cujas configurações padrão são seguras.

A senha do usuário: *user* pode ser encontrada no logo de inicialização da aplicação:
``` bash
Using generated security password: fc7e0357-7d82-4a9c-bae7-798887f7d3b3
```
O UUID nessa string é a senha. Ele será diferente para cada vez que o aplicativo for iniciado.

Conforme declarado, o Spring Security, por padrão, aceitará esse nome de usuário e senha usando o padrão de autenticação HTTP Basic, como veremos em seguida:

### Responde RESTfully a falhas de segurança
O Spring Security responde com um código de status "401 Unauthorized" quando as credenciais estão erradas ou ausentes na solicitação. Ele também, por padrão, enviará os cabeçalhos apropriados para indicar o tipo de autenticação esperado. O significado implícito do "401" é que a solicitação não é autenticada .

Ele responde com um código de status "403 Forbidden" quando as credenciais são boas, mas a solicitação não é autorizada, como quando um usuário final tenta executar uma solicitação somente de administrador. O significado implícito do 403 é que a solicitação não é autorizada.

### Protege contra solicitações maliciosas com um firewall de aplicativo
Há inúmeras outras maneiras pelas quais um agente mal-intencionado pode tentar fazer mau uso da sua API REST. Com muitas delas, a melhor prática é rejeitar a solicitação imediatamente.

O Spring Security ajuda você com isso adicionando um firewall de aplicativo que, por padrão, rejeita solicitações que contêm codificação dupla e vários caracteres inseguros, como retornos de carro e quebras de linha. Usar o firewall do Spring Security ajuda a mitigar classes inteiras de vulnerabilidades.

# Prática 1 - Tornando a Aplicação Segura com a Segurança Padrão (Security´s Defaults)
Nessa prática, adicionaremos o Spring Security ao projeto desse repositório e vamos explorar como é a proteção padrão, fornecida pelo Spring Security.

No projeto inicial, adicionar a dependência do Spring Security no arquivo pom.xml, conforme segue:

``` xml
      <dependencies>
        ...
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        ...
      </dependencies>
```

Dessa forma o Spring Security é adicionando ao *classpath*, e a autoconfiguração é feita pelo Spring Boot.
Em seguida, rode os teste da aplicação. No terminal, digite:
``` bash
> mvn tests
```

```
[ERROR]   CashCardApplicationTests.shouldCreateANewCashCard:44 Status expected:<201> but was:<403>
[ERROR]   CashCardApplicationTests.shouldReturnACashCardWhenDataIsSaved:28 Status expected:<200> but was:<401>
[ERROR]   CashCardApplicationTests.shouldReturnAllCashCardsWhenListIsRequested:57 Status expected:<200> but was:<401>
```
Os testes falharam, somente pela adição do security ao classpath. Isso devido a segurança padrão *(secure by default)* do Spring Security.

### Requer Autenticação para Todas Requests
Conforme visto anteriormente, o Spring Security requer autenticação para todos os endpoints por padrão. É por isso que os testes estão falhando, relatando que um 401 ao invés vez do código de status esperado.

Para alterar os testes para fornecer autenticação serão necessários dois passos.
1 - Confirmar que a dependência de testes, do Spring Security está adicionada ao pom.xml
``` xml
</dependencies>
    ...
    <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    ...
    </dependencies>
```

2 - Utilizar a anotação *@WithMockUser* nos testes

A dependencia de testes do Spring Security, fornece a possibilidade de simular um usuário, ou o *principal*, como se ele estivesse autenticado durante os testes.

Adicione a anotação *@WithMockUser* no topo da classe de testes *CashCardApplicationTests*
``` java
import org.springframework.security.test.context.support.WithMockUser;
...
@SpringBootTest
@AutoConfiguredMockMvc
@WithMockUser
public class CashCardApplicationTests {
 ...
```

Dessa forma o Spring Boot ira simular um usuário *user* para cada teste. Podeno assim se confirmar que a segurança da API está configurada corretamente.

Após modificar a classe de testes, execute os testes novamente:
``` bash
> mvn tests
```

``` bash
[ERROR] Tests run: 3, Failures: 1, Errors: 0, Skipped: 0, Time elapsed: 5.474 s <<< FAILURE! -- in example.cashcardoauth2.CashCardApplicationTests
[ERROR] example.cashcardoauth2.CashCardApplicationTests.shouldCreateANewCashCard -- Time elapsed: 0.023 s <<< FAILURE!
java.lang.AssertionError: Status expected:<201> but was:<403>
```

O teste *shouldCreateANewCashCard* que testa a criação de um novo cartão de crédito falhou, mas esse comportamento para uma requisição do tipo POST, era esperado.

### Requer CSRF para Todas as Solicitações com Efeitos Colaterais

Como visto, os testes passaram exceto o *shouldCreateANewCashCard*, que é um teste POST que cria um novo CashCard. Isso ocorre porque o Spring Security não autoriza POSTs sem um token CSRF.

É possívl adicionar isso na declaração MockMvc usando um dos MockMvc RequestPostProcessors do Spring Security, ou seja, csrf().

Para corrigir o teste com suporte CSRF, importe o método auxiliar estático e adicione o token CSRF à solicitação:

Primeiro, importe o método estático
``` java
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
...
void shouldCreateANewCashCard() throws Exception {
  String location = this.mvc.perform(post("/cashcards")
      .with(csrf())
   ...
```
Rodando os testes novamente, agora os 3 deverão passar.

### Requer Autenticação para todas As Requisições (Requests)

Vamos fazer uma requisição http: no endpoint */Cashcards*:
  - Inicie a aplicação através de sua IDE ou do terminal:
``` bash
> mvn spring-boot:run
```
  - Faça uma requisição a aplicação utlizando sua ferramenta preferida (Postman, HTTPie, etc), como segue:
``` bash
GET http://localhost:8080/cashcards
```
Caso esteja utilizando o HTTPie, interrogue conforme segue:
``` bash
http :8080/cashcards
```
O retorno deverá ser:
```
HTTP/1.1 401 
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Set-Cookie: JSESSIONID=CFD6DB8E3CCBBF61B4690CBCB2262C92; Path=/; HttpOnly
WWW-Authenticate: Basic realm="Realm"
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Length: 0
Date: Thu, 08 Aug 2024 18:36:25 GMT

<Response body is empty>

Response code: 401; Time: 35ms (35 ms); Content length: 0 bytes (0 B)
```  
Ao invés de obtermos as informações dos cartões de crédito, recebemos um código 401.
Isso ocorre, devido ao Spring Security, requerer autenticação para qualquer requisiçao feita a nossa aplicação Spring Boot.

Nota: Como abordado anteriormente, o Spring Security usa convenções REST ao responder a falhas de segurança: 401 para erros de autenticação, 403 para erros de autorização.

Para compreender isso ainda mais, agora tente um endpoint inexistente como este:
``` bash
GET http://localhost:8080/endpoint-nao-existente
```
Caso esteja utilizando o HTTPie, interrogue conforme segue:
``` bash
http :8080/endpoint-nao-existente
```
O retorno deverá ser:
``` bash
http :8080/endpoint-nao-existente
HTTP/1.1 401
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
```
Pode-se notar que agora, obtivemos um código 401, ao invés do código 404 que obtinhamos, antes da aplicação ter sido protegida. Essa estratégia é defensiva, para que informação protegida não seja compartilhada de forma publica.

### Verifique os cabeçalhos
Anteriormente vimos que o Spring Security "Responde com Cabeçalhos Seguros para Todas as Requisições". Podemos ver esse princípio em ação em nossos testes recém executados.
``` bash
...
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
...
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

# Prática 2 - Utilizando HTTP Basic e o Usuário Padrão:

Localize a senha padrão, fornecida no log da aplicação Spring Boot:

Interrogue a aplicação, agora passando as credenciais:
```bash
http -a user:6cc833e4-... :8080/cashcards
```
Caso esteja utilizando Postman, configure a requisição conforme segue:
![image](https://github.com/user-attachments/assets/6a03e4e3-cd2c-49a6-800f-af040a818dc9)

A resposta deverá conter os cartões de crédito:

``` bash
http -a user:722a6428-d501-4a91-9785-5276835890d1 :8080/cashcards
HTTP/1.1 200 
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Connection: keep-alive
Content-Type: application/json
Date: Thu, 08 Aug 2024 19:10:11 GMT
Expires: 0
Keep-Alive: timeout=60
Pragma: no-cache
Transfer-Encoding: chunked
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0

[
    {
        "amount": 123.45,
        "id": 99,
        "owner": "sarah1"
    },
    {
        "amount": 1.0,
        "id": 100,
        "owner": "sarah1"
    },
    {
        "amount": 150.0,
        "id": 101,
        "owner": "esuez5"
    }
]
```
Feito isso, novamente, interrogue a aplicação, agora passando as credenciais agora com um endpoint que não exista:
``` bash
http -a user:6cc833e4-... :8080/endpoint-inexistente
```
Interrogando via Postman:
![img.png](img.png)

# Adicionando Autenticação

Veremos agora Spring Security como uma estrutura para autenticação de requisições. Isso significa confirmar:

A identidade do chamador - quem fez a solicitação, às vezes chamou para o cliente ou para o agente
A identidade do principal - sobre quem é a solicitação, geralmente um usuário final
A integridade da solicitação - prova de que a solicitação não foi modificada por um intermediário
Cada um deles pode ser bastante complexo de garantir, e é por isso que recorrer a protocolos e estruturas de segurança para obter suporte é estrategicamente importante.

Nota: Principal é um termo genérico que representa "quem" está fazendo a solicitação. A razão pela qual usamos principal é porque às vezes o "quem" não é uma pessoa, mas sim outra máquina.

## Negociação de Conteúdo
As configurações padrão do Spring Security confirmam a identidade do principal usando os esquemas de autenticação Form Login e HTTP Basic. Ele usa negociação de conteúdo para selecionar entre os dois.

Por exemplo, se um navegador navega para um endpoint não autenticado na sua API, então, por padrão, o Spring Security redireciona para sua página de login padrão, que se parece com esta:
![image](https://github.com/user-attachments/assets/49e64d9c-a7fc-4273-99e0-4816b02f18b5)

Por outro lado, se alguém fizer uma solicitação REST não autenticada como esta:
``` bash
[~/exercises] $ http :8080
```

Em seguida, o Spring Security usa o cabeçalho WWW-Authenticate para indicar qual esquema de autenticação ele espera:
``` bash
WWW-Authenticate: Basic
```

Em vez disso, se a solicitação REST fornecer um cabeçalho Authorization seguindo o esquema HTTP Basic:
``` bash
[~/exercises] $ http :8080 "Authorization: Basic dXNlcjpwYXNzd29yZA=="
```

Nota: O comando do HTTPie http -a adicionará o cabeçalho Authorization: Basic para você se você passar oparâmetro "-a" . Acima, adicionamos o cabeçalho manualmente.

O Spring Security vê o esquema Básico e exerce seu suporte de autenticação HTTP Básico.

## Processo de autenticação
Para detalhar um pouco mais, você pode pensar no suporte de autenticação do Spring Security em três partes, independentemente do esquema de autenticação usado:

1 - Ele analisa o material solicitado em uma credencial.

2 - Ele testa essa credencial.

3 - Se a credencial for aprovada, ela traduz essa credencial em um "principal" e suas autoridades.

No caso acima, você pode ver essas três etapas em ação:

1 - O Spring Security decodifica o nome de usuário e a senha codificados em Base64. A senha é a credencial neste caso.

2 - Ele testa esse nome de usuário e senha em relação a um armazenamento de usuário. Especificamente, com senhas, ele faz o hash da senha e a compara ao hash da senha do usuário.

3 - Se as senhas corresponderem, ele carrega o usuário e as permissões correspondentes e os armazena em seu contexto de segurança (security context). O usuário resultante é o principal que mencionamos anteriormente.

Todos os esquemas de autenticação seguem essa abordagem geral no Spring Security.

## Solicitações subsequentes

Alguns esquemas de autenticação são *stateful*, enquanto outros são *stateless*. *Stateful* significa que seu aplicativo lembra informações sobre requisições anteriores. *Stateless* significa que seu aplicativo não lembrará requisições anteriores.

Os dois esquemas de autenticação padrão são bons exemplos de cada um. O Form Login é um exemplo de um esquema de autenticação *stateful*. Ele armazena o usuário logado em uma sessão. Desde que o identificador da sessão seja retornado em solicitações subsequentes, o usuário final não precisa fornecer credenciais novamente. Para muitos sites, é por isso que você não precisa fazer login a cada nova página que visita no site.

HTTP Basic é um exemplo de esquema de autenticação *stateless*. Como ele não lembra nada de solicitações anteriores, você precisa dar a ele o nome de usuário e a senha em cada solicitação.

Observação: lembre-se de que o Spring Security ativa os esquemas de autenticação HTTP Basic e Form Login por padrão. Você pode especificá-los e outros diretamente com uma instância personalizada SecurityFilterChain. Caso essa instância personalizada não seja configurada, o Spring Boot autoconfigura a mesma de forma básica.

## Limites do HTTP Basic

O Spring Security ativa o HTTP Basic por padrão, pois é uma maneira fácil e direta para começar. Porém, esse modelo de autenticação é limitado.

Em de forma geral, as limitações são:

* Credenciais de longo prazo
* Bypass de autorização e
* Exposição de dados sensíveis
Antes de analisá-los, considere um arranjo comum de um aplicativo que usa HTTP Basic entre um cliente e uma API REST:

``` mermaid
flowchart LR
    id1((User)) -- Fornece a senha --> id2([Client *App*])
    id2 -- Basic Auth --> id3([Rest API *Seus dados*])
```
Neste diagrama, há um aplicativo cliente que usa seu nome de usuário e senha para trocar informações com uma API REST em seu nome. Um exemplo disso é um aplicativo de orçamento de terceiros que quer chamar uma API REST e importar transações.

## Credenciais de longo prazo
Para entender essa primeira limitação, considere isto: quando foi a última vez que você alterou a senha da sua conta online menos usada? Em muitos casos, a resposta é da ordem de anos!

Se uma API REST usa seu nome de usuário e senha como credenciais, isso significa que qualquer um que obtiver seu nome de usuário e senha pode se passar por você enquanto sua senha for válida.

Mesmo que você pudesse mudar todas as suas senhas em todos os sistemas semanalmente, qual das suas contas você aceitaria conceder acesso a um malfeitor por uma semana inteira?

Dado isso, a principal limitação do HTTP Basic é que ele usa uma credencial de longo prazo que exige que o usuário final a altere.

## Bypass de autorização
Outra limitação é que quando você fornece seu nome de usuário e senha da API REST a um cliente terceirizado, esse aplicativo passa a ter posse do seu nome de usuário e senha.

Embora isso possa parecer óbvio, significa que você precisa perguntar agora: Você confia que esse aplicativo usará seu nome de usuário e senha apenas para os propósitos que você deseja? Além disso, você tem que confiar que esse aplicativo não será comprometido por atores ruins em quem você não confia.

Seria bom se houvesse uma maneira de ter uma credencial que, além de ser de curto prazo, também indicasse quais coisas você autoriza o cliente a fazer com seus dados.

## Exposição de dados sensíveis
Lembre-se de que o HTTP Basic é stateless. Sempre que um aplicativo cliente de terceiros chama a REST API, ele precisa entregar seu nome de usuário e senha toda vez que você faz uma solicitação HTTP.

Além disso, isso significa que o aplicativo cliente precisa manter seu nome de usuário e senha em texto simples em algum lugar para que ele possa repassá-los repetidamente para a API REST.

Isso significa que uma única solicitação HTTP interceptada ou um único despejo de memória de um aplicativo cliente pode revelar sua senha!

Então, além de ter uma credencial de curto prazo que seja inteligente o suficiente para autorizar ações específicas, sua senha não deve ser mantida (em texto simples ou não) por terceiros em lugar nenhum. Nunca.

# OAuth 2.0 e JWT
## OAuth 2.0
Lembre-se de que uma preocupação primária de segurança é que as senhas são credenciais altamente sensíveis de longo prazo. Seria melhor ter credenciais que durassem apenas alguns minutos. Mas, não é realista para nós, humanos, mudar constantemente nossas senhas.

OAuth 2.0 – um protocolo padrão da indústria para autorização que foi adotado por milhares de empresas e usado em milhões de aplicativos – fornece uma estrutura para fazer exatamente isso.

Em resumo, o OAuth 2.0 descreve três atores:

* O aplicativo cliente, que deseja acessar seus dados e fornecer serviços, geralmente um aplicativo da web, móvel ou desktop.
* O Servidor de Recursos, que armazena e protege seus dados, geralmente uma API REST.
* O Servidor de Autorização, que autoriza um cliente a acessar seus dados.
``` mermaid
flowchart LR
    id1((User)) --> id2([Client *app*])
    id2 -- Envia o Token --> id3([Resource *Seus Dados*])
    id2 -- Solicita o Token --> id4([Authz *app*])
    id4 -- Fornece o Token --> id2
```

Esses três atores interagem entre si da seguinte maneira:

- O aplicativo cliente solicita ao servidor de autorização permissão para comandar o servidor de recursos.
- O servidor de autorização decide se concede ou não permissão.
- Se o servidor de autorização conceder permissão, ele cria um token de acesso que expira após um período de tempo. Este token de acesso descreve quais permissões o cliente recebeu
- O cliente faz uma solicitação ao servidor de recursos, incluindo o token de acesso.
- O servidor de recursos verifica se o token de acesso tem as permissões corretas e responde adequadamente.
Dessa forma, o aplicativo cliente nunca vê sua senha.

## JSON Web Tokens
JSON Web Token (JWT) é um formato padrão da indústria para codificação de tokens de acesso. Quando um servidor de autorização cria um token de acesso, ele pode escrevê-lo no formato JWT, que é amplamente difundido.

Um JWT decodificado em sua forma mais básica é um conjunto de cabeçalhos e declarações:

Os cabeçalhos contêm metadados sobre o token.
Claims são fatos que o token está afirmando, como qual principal o token representa. Elas são chamadas de "claims" porque ainda precisam ser verificadas pelo servidor de recursos – o JWT "reivindica" que esses fatos sejam verdadeiros.

Exemplo:

```  json
{
  "typ": "JWT",
  "alg": "RS256"
}

```
``` json
+cabeçalhos
{
  "aud": "https://cashcard.example.org",
  "exp": 1689364985,
  "iat": 1689361385,
  "iss": "https://issuer.example.org",
  "scp": ["cashcard:read", "cashcard:write"],
  "sub": "sarah1"
}
```
+reivindicações (claims)

A declaração iss identifica o servidor de autorização que cunhou (gerou) o token.
A declaração exp indica quando o token expira.
A declaração scp (scope) indica o conjunto de permissões concedidas pelo servidor de autorização.
A sub reivindicação é uma referência ao principal que o token representa.
Uma informação crítica é a assinatura do JWT. Pense em uma assinatura como sua assinatura em um contrato. Uma boa assinatura só pode ser produzida por uma entidade, que nos fornece o que é chamado de *não-repúdio (non-repudiation)*, ou prova de que o contrato foi assinado por você e somente você.

Na criptografia, uma assinatura também fornece *integridade de mensagem*, ou prova de que a mensagem não foi alterada por ninguém depois. Você pode, neste caso, pensar no selo de não adulteração em uma embalagem no mercado. Se o selo estiver quebrado, você não deve comprá-lo, pois isso significa que alguém pode ter adulterado.

Parte do processo de criação é para o servidor de autorização assinar o JWT. Então, o servidor de recursos verifica essa assinatura. Isso permite que o servidor de recursos confirme a integridade da solicitação, além da identidade do principal.


## Suporte Spring Boot
O Spring Security é totalmente compatível, com JWT e Spring Security, fornecendo recursos que facilitam a configuração de segurança para utilização de JWT.

Para servidores de recursos, vamos revisar as etapas vistas anteriormente sobre como o Spring Security processa a autenticação:

Ele analisa o contéudo de solicitação em uma credencial. O Spring Security procura por *Authorization: Bearer ${JWT}*.

Ele testa essa credencial. O Spring Security usa uma instância *JwtDecoder* para consultar o servidor de autorização em busca de chaves, usa essas chaves para verificar a assinatura dos JWTs e valida que é de um emissor confiável e ainda está dentro da janela de expiração.

Se a credencial for aprovada, ela traduz essa credencial em um *principal* e *autoridades*. O Spring Security armazena as declarações do JWT como o principal. Ele pega a declaração *scope* e analisa cada valor individualmente em uma permissão com o padrão *SCOPE_${value}*.

Esse princípio e essas autoridades são então armazenados pelo Spring Security e ficam acessíveis durante o restante da solicitação.

# Prática 3 - Adicionando a depedência do Oauth Resource Server ao Projeto

Agora vamos modificar o método de autenticação de Basic para Oauth
Para isso precisamos primeiramente adicionar as seguintes dependências ao projeto:

``` xml
<dependencies>
  ...
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
  </dependency>
  ...
</dependencies>
```
Dessa forma o Spring Boot se autoconfigurará, e adicionará os módulos Spring Boot Resource Server e JWT ao projeto.

## Configurando o Resource Server

Agora precisamos como a nossa API REST, que agora é um resource server Oauth 2.0, irá verificar as assinaturas JWT. Normalmente se utilizam chaves públicas para verificar essas assinaturas, sendo assim, utiliza as chaves públicas contidas nesse repositório [chaves colocar o link aqui]().
Faça a seguinte configuração no application.properties:
``` bash
spring.security.oauth2.resourceserver.jwt.public-key-location = classpath:authz.pub
```
Certifique-se de a chave authz.pub está no diretório *resources* do projeto.

Após configurar o Resource Server, o Spring Boot ativará a auto configuração do nosso resource server.

## Verifique se os testes ainda funcionam   **v e r i f i c a r**
``` bash
mvn test
```
Como ainda não existem testes específicos para o protocoloo, o Spring Security adatou os existentes e os mesmos deverão passar.

## Por dentro do Resource Server
Verificaremos de forma uma pouco mais profunda, os logs do Spring Security. Para isso iremos melhorar os logs de informação, adicionando a seguinte configuração ao *application.properties*:
``` bash
logging.level.org.springframework.security = trace
```
Em seguida rode a aplicação novamente:
``` bash
mvn spring-boot:run
```
Não deverão mais ser criados, o usuário (user) e senha padrão, gerados anteriomente pelo Spring Security.

## Verificando o método de autenticação
Interrogue a aplicação, conforme segue:
``` bash
http :8080/cashcards
```
Espera-se que a requisição falhe, retornando um *401*, porém, a resposta deverá conter no cabeçalho, algo conforme segue:
``` http
HTTP/1.1 401
...
WWW-Authenticate: Bearer
...
```
## Autenticando uma Requisição
Como agora estamos trabalhando com um Resource Server, precisamos providenciar um JSON Web Token para adicionarmos a nossas requisições. Faremos isso da seguinte forma:

## Configurando a geração de tokens
Normalmente, o JWT viria de um aplicativo cliente solicitando autorização de um servidor de autorização. Como ainda não dispomos de tal recursos, vamos editar nossa aplicação.

Crie uma nova classe CashCardJwtTokenGenerator.java:
``` java
package example.cashcardoauth2;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.function.Consumer;
import java.util.logging.Logger;

@Component
public class CashCardJwtTokenGenerator {

    private static final Logger LOGGER = Logger.getLogger(CashCardTokenGen.class.getName());

    @Autowired
    JwtEncoder jwtEncoder;

    public String mint() {
        return mint(consumer -> {
        });
    }

    private String mint(Consumer<JwtClaimsSet.Builder> consumer) {
        JwtClaimsSet.Builder builder = JwtClaimsSet.builder().issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(200000)).subject("sarah1").issuer("http://localhost:8080").audience(Arrays.asList("cashcard-client")).claim("scp", Arrays.asList("cashcard:read", "cashcard:write"));
        consumer.accept(builder);
        JwtEncoderParameters parameters = JwtEncoderParameters.from(builder.build());
        return this.jwtEncoder.encode(parameters).getTokenValue();
    }

    @PostConstruct
    public void logTokenOnInitialization() {
        String token = mint();
        LOGGER.info("Generated JWT on startup: " + token);
    }

    @Configuration
    static class jwtEncoderConfiguration {
        @Bean
        JwtEncoder jwtEncoder(@Value("classpath:authz.pub") RSAPublicKey pub, @Value("classpath:authz.pem") RSAPrivateKey pem) {
            RSAKey key = new RSAKey.Builder(pub).privateKey(pem).build();
            return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
        }

        @Bean
        public JwtDecoder jwtDecoder(@Value("classpath:authz.pub") RSAPublicKey pub) {
            return NimbusJwtDecoder.withPublicKey(pub).build();
        }
    }

}
```
Essa classe, irá gerar um token JWT, de forma análoga ao esquema antigo, onde a cada incialização, um user e password eram gerados. Vale lembrar, que isso só está sendo feito para fins acadêmicos, e não deve jamais ser utilizado em produção.
Pode-se, notar que estão sendo configurados beans para o JwtEncoder, o JwtDecoder e método mint, para esculpir ou criar o token em si. Nota-se que para codificar um token, são utilizadas as ambas a chaves, e para decodificar um token, somente a chave pública.

Adicionar explicação sobre como o token é gerado
``` java
  JwtClaimsSet
    .builder()
      .issuedAt(Instant.now()) //Inicio da validade do token
      .expiresAt(Instant.now()
      .plusSeconds(200000))  // //Fim da validade do token
      .subject("sarah1")    // User or principal, para qual o token é atribuído
      .issuer("http://localhost:8080")    //Emissor do token (verificar no application.properties)
      .audience(Arrays.asList("cashcard-client")) //Espectador do token (verificar no application.properties)
      .claim("scp", Arrays.asList("cashcard:read", "cashcard:write")); //Reinvindicações (claims) do token. 
```
Após a configurarmos a geração do token, rodar a aplicação:
``` bash
mvn spring-boot:run
```
Veja que um token foi gerado, assim que aplicação foi inicializada:
``` bash
2024-08-13T10:25:45.771-03:00  INFO 21392 --- [CashCardOauth2] [           main] e.c.CashCardJwtTokenGenerator            : Generated JWT on startup: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzYXJhaDEiLCJhdWQiOiJjYXNoY2FyZC1jbGllbnQiLCJzY3AiOlsiY2FzaGNhcmQ6cmVhZCIsImNhc2hjYXJkOndyaXRlIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImV4cCI6MTcyMzc1NTU0NSwiaWF0IjoxNzIzNTU1NTQ1fQ.qwQKlphaor5do2FTGdtyXPRuxdkeC5COUQ6Yy27JT0Ll7dR74lhseDPQqNmqR_wOwW7P4zzfS8sEeT1UMQC2pgtIj7dOBK3uMwOtzFHrFBH5XDYufIUXJUU4YcQVUb4Kc2qgHEC4YTZMq3YDDB1OYDQAz104vkWpkjDWc5tVxggSwJE1xnqHXr7o52HrseRG9J-b3HEwE2d1HDz7XQiSL0kvRy9sROmWxvw0qDrwWghiOl6qkRovzw5oL-dsrZ1pgV2KTHk58fCXhWnzpmqEFuhBIbWzY0b_IXIjubbqIj57_5aYrR7yjoTUiT9mObaE7i3yYEBTkEh-1sK4KlQTag
```
Vamos agora, inspecionar o conteúdo desse token, fazendo sua decodificação. Para tal utilizaremos a seguinte ferramenta:
[jwt.io](https://jwt.io/)

Agora, copie o token gerado, e utilize o jwt.io, para decodificar o token:
![image](https://github.com/user-attachments/assets/caac30fe-2074-4360-b169-4a6067dd2061)

Como é possível verificar, o token carrega as configurações que acabamos de carregar na classe CashCardJwtTokenGenerator.java.

## Interrogar a aplicação com o token
``` bash
http :8080/cashcards "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzYXJhaDEiLCJhdWQiOiJjYXNoY2FyZC1jbGllbnQiLCJzY3AiOlsiY2FzaGNhcmQ6cmVhZCIsImNhc2hjYXJkOndyaXRlIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImV4cCI6MTcyMzc1OTMzNiwiaWF0IjoxNzIzNTU5MzM2fQ.VrA3MLB9VvIq4oT5uhRM5UL1N7LyJeSQTx-1mIYzaWPsjLpTjkap7jvv8wiB3d5P2sEZlljxu_cGELeQxkTCHVm0GFRfK0rlXGQ6ut3CgzIXxiluXNIrn9sfJMYla9tqMY9G0fhZqscGonEMCD6bBOhvHoopPPo74iLSyuG8ZkJD0b26rxhp9prz7DNTf8U7dq-bYv40L2sXb1r31IxphgEbIU2fUpjFr2IWHaOnmbuucPO1gJYpKYE3SDfHPYoAKCdNr9Tt5lDjSoqGT_0g7AJcaH0sOtPl-xaZLsybnMunhYYeQrClpqs6q0c0-nOzAL5JFiz58alJlFUAcpU3Pg"
```
Ou se desejar, a mesma requisição pode ser feita via Postman, conforme abaixo:
![image](https://github.com/user-attachments/assets/74715645-a69e-468b-9657-fd5c909359d0)

 O retorno esperado deve ser algo parecido com o que segue:
 ``` bash
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Connection: keep-alive
Content-Type: application/json
Date: Tue, 13 Aug 2024 14:34:57 GMT
Expires: 0
Keep-Alive: timeout=60
Pragma: no-cache
Transfer-Encoding: chunked
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0

[
    {
        "amount": 123.45,
        "id": 99,
        "owner": "sarah1"
    },
    {
        "amount": 1.0,
        "id": 100,
        "owner": "sarah1"
    },
    {
        "amount": 150.0,
        "id": 101,
        "owner": "esuez5"
    }
]
```
Veja que o retorno, inclui as informações de outro usuário, diferente do usuário que está configurado no token. Veremos em seguida uma das maneiras para resolver esse problema.

## A Instância de Autenticação:

Observando os logs de nossa aplicação, podemos observar o seguinte:
``` bash
JwtAuthenticationToken [Principal=org.springframework.security.oauth2.jwt.Jwt@da5265e9, Credentials=[PROTECTED], Authenticated=true, Details=WebAuthenticationDetails [RemoteIpAddress=127.0.0.1, SessionId=null], Granted Authorities=[SCOPE_cashcard:read, SCOPE_cashcard:write]]
```
Como é possível observar a instância gerada, carrega as seguintes informações:
* Um *principal*, que é o conjunto de reivindicações
* Uma *credencial*, que é o JWT original assinado e
* Um conjunto de *autoridades, cada escopo prefixado por SCOPE_
  
Você pode ver que a instância de autenticação para nosso aplicativo Cash Card é: SCOPE_cashcard:read e SCOPE_cashcard:write.

# Acessando Informações de Autenticação
## O Security Context Holder
Para acessar informações sobre a instância do *principal* que está utilizando nossa aplicação vamos utilizar o SecurityContext.
Ex.:
```java
SecurityContext context = SecurityContextHolder.getContext();
Authentication authentication = context.getAuthentication();
```
Para por exemplo, modificarmos o método findAll() para que o mesmo busque somente as informações do próprio *owner*, ficaria assim:

```java
@GetMapping
public ResponseEntity<Iterable<CashCard>> findAll() {
    Jwt owner = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    return ResponseEntity.ok(this.cashCards.findByOwner(owner.getSubject()));
}
```

O Security Context, normalmente, é utilizado em classes, as quais não são gerenciadas pelo Spring Boot, ou em outras palavras, em classes que não sejam beans.
Se você se encontrar dentro de um objeto Java simples e antigo, ou POJO, e precisar do SecurityContext, SecurityContextHolder.getContext()é uma opção válida.
O *SecurityContextHolder* usa a *ThreadLocal* para armazenar o contexto de segurança, o que significa que ele é específico para o thread atual. Portanto, você pode acessar as informações de autenticação dentro do mesmo thread em todo o seu aplicativo.

# Prática 4 - Personalizando a busca de Cartões

Como visto anteriormente, ao interrogarmos a aplicação, no endpoint *cashcards*, mesmo com o token, tendo em seu conteúdo, informações sobre o usuário e seus escopos, a busca por cartões estava retornando informações de todos os usuários, e não somente as que pertencem ao usuário que está solicitando essas informações.
Para resolver esse problema, vamos editar a classe *CashCardRepository.java*:
```java
package example.cashcardoauth2;

import org.springframework.data.repository.CrudRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Repository;

@Repository
public interface CashCardRepository extends CrudRepository<CashCard, Long> {
    Iterable<CashCard> findByOwner(String owner);

    default Iterable<CashCard> findAll() {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        String owner = (String) authentication.getName();
        return findByOwner(owner);
    }
}
```
Aqui utilizamos o SecurityContextHolder, para descobrirmos qual é o usuário que está interrogando a aplicação.
Essas informações, ficam no token, que geramos anteriormente.
Dessa forma, é possível buscar as informações pertencentes somente ao usuário que é dono das mesmas.

### Interrogar a aplicação novamente
``` bash
http :8080/cashcards "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzYXJhaDEiLCJhdWQiOiJjYXNoY2FyZC1jbGllbnQiLCJzY3AiOlsiY2FzaGNhcmQ6cmVhZCIsImNhc2hjYXJkOndyaXRlIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImV4cCI6MTcyMzc1OTMzNiwiaWF0IjoxNzIzNTU5MzM2fQ.VrA3MLB9VvIq4oT5uhRM5UL1N7LyJeSQTx-1mIYzaWPsjLpTjkap7jvv8wiB3d5P2sEZlljxu_cGELeQxkTCHVm0GFRfK0rlXGQ6ut3CgzIXxiluXNIrn9sfJMYla9tqMY9G0fhZqscGonEMCD6bBOhvHoopPPo74iLSyuG8ZkJD0b26rxhp9prz7DNTf8U7dq-bYv40L2sXb1r31IxphgEbIU2fUpjFr2IWHaOnmbuucPO1gJYpKYE3SDfHPYoAKCdNr9Tt5lDjSoqGT_0g7AJcaH0sOtPl-xaZLsybnMunhYYeQrClpqs6q0c0-nOzAL5JFiz58alJlFUAcpU3Pg"
```
O retorno, dessa vez, deverá ser somente do proprietário do token:
```bash
Connection: keep-alive
Content-Type: application/json
Date: Tue, 13 Aug 2024 15:32:42 GMT
Expires: 0
Keep-Alive: timeout=60
Pragma: no-cache
Transfer-Encoding: chunked
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0

[
    {
        "amount": 123.45,
        "id": 99,
        "owner": "sarah1"
    },
    {
        "amount": 1.0,
        "id": 100,
        "owner": "sarah1"
    }
]
```
