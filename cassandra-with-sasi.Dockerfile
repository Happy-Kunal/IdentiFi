FROM cassandra:4.1

# enabling sasi_indexes
RUN sed -i -r 's/sasi_indexes_enabled: false/sasi_indexes_enabled: true/' /etc/cassandra/cassandra.yaml
