dnsspoof
========

Falsificador de DNS. Descarta as respostas DNS antes que elas cheguem ao roteador e as substitui pela resposta DNS falsificada.

Usage
------

```shell
python dnsspoof.py -r 192.168.0.1 -v 192.168.0.5 -d domaintospoof.com
```

Falsificar domaintospoof.com para apontar de volta para a máquina do ataque.


```shell
python dnsspoof.py -r 192.168.0.1 -v 192.168.0.5 -a -t 80.87.128.67
```

Falsifique todas as solicitações de pesquisa de DNS para apontar para 80.87.128.67 (stallman.org). Também é possível usar a opção -t com a opção -d para redirecionar apenas um domínio específico para um IP específico, em vez de redirecionar aquele

-------

Recomendo o uso do pyphisher para criar páginas de phishing e o usar no DNS Spoofing
-------
danmcinerney.org
modificado por Wrench
