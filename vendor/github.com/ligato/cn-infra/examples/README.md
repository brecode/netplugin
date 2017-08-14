# CN-infra examples

There are several `main.go` files used as an illustration of the cn-infra functionality. Most of the examples show
a very simple use case using the real ETCD and/or Kafka plugins, so for specific examples, they have to be started at first.

Current examples:
* **[etcd](etcd/main.go)** uses the ETCD data broker to write a data which are then caught by the watcher
* **[flags](flags/main.go)** example registers flags and shows their runtime values
* **[kafka](kafka/main.go)** creates simple plugin which registers Kafka consumer and sends a test notification
* **[logs](logs/main.go)** shows the logger and log level usage

## How to run example

 **1. Start ETCD server on localhost**

  ```
  sudo docker run -p 2379:2379 --name etcd --rm \
  quay.io/coreos/etcd:v3.0.16 /usr/local/bin/etcd \
  -advertise-client-urls http://0.0.0.0:2379 \
  -listen-client-urls http://0.0.0.0:2379
  ```

 **2. Start Kafka**

 ```
 sudo docker run -p 2181:2181 -p 9092:9092 --name kafka --rm \
  --env ADVERTISED_HOST=172.17.0.1 --env ADVERTISED_PORT=9092 spotify/kafka
 ```

 **3. Start desired example**

 Example can be started now from particular directory.
 ```
 go run main.go  \
 --etcdv3-config=/opt/vnf-agent/dev/etcd.conf \
 --kafka-config=/opt/vnf-agent/dev/kafka.conf
 ```
