# SpringSecurityOoauth

Nesse repositório serão abordados os seguintes assuntos:

* Entenda os conceitos básicos de autenticação, autorização e proteção de aplicativos da web
* Identificar e avaliar opções de autenticação e autorização
* Proteja uma API REST usando o suporte do servidor de recursos OAuth 2.0 do Spring Security
* Endpoints Spring MVC seguros e consultas Spring Data usando primitivas Spring Security
* Teste seu aplicativo com a segurança habilitada

  # A API Rest sem segurança
  Clone a aplicação, para que façamos algumas observações.

Clone a aplicação desse repositório, em seguida, inicie-a.
Em seguinda, utilizando uma ferramente para requisições Http (Como Postman, HTTPie, ou outra de sua preferência), faça uma requisição conforme segue:
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

