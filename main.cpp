#include <boost/python.hpp>
namespace python = boost::python;

#include <bitcoin/bitcoin.hpp>
#include <bitcoin/blockchain/bdb_blockchain.hpp>
namespace ph = std::placeholders;

class ensure_gil
{
public:
    ensure_gil()
    {
        state_ = PyGILState_Ensure();
    }
    ~ensure_gil()
    {
        PyGILState_Release(state_);
    }
private:
    PyGILState_STATE state_;
};

template <typename... Args>
class pyfunction
{
public:
    pyfunction(python::object callable)
      : callable_(callable)
    {
    }

    void operator()(Args... params)
    {
        ensure_gil eg;
        try
        {
            callable_(std::forward<Args>(params)...);
        }
        catch (const python::error_already_set&)
        {
            PyErr_Print();
            python::handle_exception();
        }
    }
private:
    python::object callable_;
};

template<class T>
class std_item
{
public:
    typedef typename T::value_type V;

    static T create_array(boost::python::list l)
    {
        T result;
        for (size_t i = 0; i < result.size() && i < len(l); ++i)
            result[i] = python::extract<typename T::value_type>(l[i]);
        return result;
    }
    static T create_vector(boost::python::list passed)
    {
        T result;
        for (size_t i = 0; i < len(passed); ++i)
            result.push_back(
                python::extract<typename T::value_type>(passed[i]));
        return result;
    }

    static V get(const T& x, int i)
    {
        if (!is_valid_index(i, x.size()))
            index_error();
        return x[i];
    }

    static void set(T& x, int i, const V& v)
    {
        if (!is_valid_index(i, x.size()))
            index_error();
        x[i] = v;
    }

    static void del(T& x, int i)
    {
        if (!is_valid_index(i, x.size()))
            index_error();
        x.erase(x.begin() + i);
    }

    static void add(T& x, const V& v)
    {
        x.push_back(v);
    }
private:
    static void index_error()
    { 
        PyErr_SetString(PyExc_IndexError, "Index out of range");
        throw boost::python::error_already_set();
    }

    static bool is_valid_index(int& idx, size_t size)
    {
        if (idx < 0)
            idx += size;
        if (idx >= 0 && idx < static_cast<int>(size))
            return true;
        return false;
    }
};

class error_code_wrapper
{
public:
    static bool nonzero(const std::error_code& ec)
    {
        return (bool)ec;
    }
    static bool eq(const std::error_code& eca, bc::error::error_code_t err)
    {
        return eca == err;
    }
};

class atomic_counter_wrapper
{
public:
    atomic_counter_wrapper(size_t initial_value)
    {
        counter_ = std::make_shared<bc::atomic_counter>(initial_value);
    }

    void increment()
    {
        ++(*counter_);
    }

    size_t count() const
    {
        return *counter_;
    }
private:
    bc::atomic_counter_ptr counter_;
};

struct async_service_wrapper
{
    async_service_wrapper()
    {
        s = std::make_shared<bc::async_service>();
    }
    async_service_wrapper(size_t n)
    {
        s = std::make_shared<bc::async_service>(n);
    }
    void spawn()
    {
        s->spawn();
    }
    void shutdown()
    {
        s->shutdown();
    }
    std::shared_ptr<bc::async_service> s;
};

class acceptor_wrapper
{
public:
    acceptor_wrapper(bc::acceptor_ptr accept)
      : accept_(accept)
    {
    }
    void accept(python::object handle_accept)
    {
        accept_->accept(
            std::bind(&acceptor_wrapper::call_handle_accept,
                ph::_1, ph::_2, handle_accept));
    }
private:
    static void call_handle_accept(const std::error_code& ec,
        bc::channel_ptr node, python::object handle_accept)
    {
        handle_accept(ec, node);
    }
    bc::acceptor_ptr accept_;
};

class channel_wrapper
{
public:
    channel_wrapper(bc::channel_ptr node)
      : node_(node)
    {
    }

    void stop()
    {
        node_->stop();
    }
    bool stopped() const
    {
        return node_->stopped();
    }

    template <typename Message>
    void send(const Message& packet, python::object handle_send)
    {
        node_->send(packet, pyfunction<const std::error_code&>(handle_send));
    }
    void send_raw(const bc::message::header& packet,
        const bc::data_chunk& payload, python::object handle_send)
    {
        node_->send_raw(packet, payload,
            pyfunction<const std::error_code&>(handle_send));
    }

    void subscribe_version(python::object handle_receive)
    {
        node_->subscribe_version(pyfunction<const std::error_code&,
            const bc::message::version&>(handle_receive));
    }
    void subscribe_verack(python::object handle_receive)
    {
        node_->subscribe_verack(pyfunction<const std::error_code&,
            const bc::message::verack&>(handle_receive));
    }
    void subscribe_address(python::object handle_receive)
    {
        node_->subscribe_address(pyfunction<const std::error_code&,
            const bc::message::address&>(handle_receive));
    }
    void subscribe_get_address(python::object handle_receive)
    {
        node_->subscribe_get_address(pyfunction<const std::error_code&,
            const bc::message::get_address&>(handle_receive));
    }
    void subscribe_inventory(python::object handle_receive)
    {
        node_->subscribe_inventory(pyfunction<const std::error_code&,
            const bc::message::inventory&>(handle_receive));
    }
    void subscribe_get_data(python::object handle_receive)
    {
        node_->subscribe_get_data(pyfunction<const std::error_code&,
            const bc::message::get_data&>(handle_receive));
    }
    void subscribe_get_blocks(python::object handle_receive)
    {
        node_->subscribe_get_blocks(pyfunction<const std::error_code&,
            const bc::message::get_blocks&>(handle_receive));
    }
    void subscribe_transaction(python::object handle_receive)
    {
        node_->subscribe_transaction(pyfunction<const std::error_code&,
            const bc::message::transaction&>(handle_receive));
    }
    void subscribe_block(python::object handle_receive)
    {
        node_->subscribe_block(pyfunction<const std::error_code&,
            const bc::message::block&>(handle_receive));
    }
    void subscribe_raw(python::object handle_receive)
    {
        node_->subscribe_raw(pyfunction<
            const std::error_code&, const bc::message::header&,
            const bc::data_chunk&>(handle_receive));
    }

    bc::channel_ptr channel() const
    {
        return node_;
    }
private:
    bc::channel_ptr node_;
};

class network_wrapper
{
public:
    network_wrapper(async_service_wrapper service)
    {
        net_ = std::make_shared<bc::network>(*service.s);
    }
    void listen(uint16_t port, python::object handle_listen)
    {
        net_->listen(port,
            std::bind(&network_wrapper::post_listen,
                ph::_1, ph::_2, handle_listen));
    }
    void connect(const std::string& hostname, uint16_t port,
        python::object handle_connect)
    {
        net_->connect(hostname, port,
            std::bind(&network_wrapper::post_connect,
                ph::_1, ph::_2, handle_connect));
    }

    bc::network_ptr net() const
    {
        return net_;
    }
private:
    static void post_listen(const std::error_code& ec,
        bc::acceptor_ptr accept, python::object handle_listen)
    {
        ensure_gil eg;
        pyfunction<const std::error_code&,
            acceptor_wrapper> f(handle_listen);
        f(ec, acceptor_wrapper(accept));
    }
    static void post_connect(const std::error_code& ec,
        bc::channel_ptr node, python::object handle_connect)
    {
        ensure_gil eg;
        pyfunction<const std::error_code&,
            channel_wrapper> f(handle_connect);
        f(ec, channel_wrapper(node));
    }
    bc::network_ptr net_;
};

class handshake_wrapper
{
public:
    handshake_wrapper(async_service_wrapper service)
    {
        hs_ = std::make_shared<bc::handshake>(*service.s);
    }
    void start(python::object handle_start)
    {
        hs_->start(
            pyfunction<const std::error_code&>(handle_start));
    }
    void connect(network_wrapper net_wrap, const std::string& hostname,
        uint16_t port, python::object handle_connect)
    {
        hs_->connect(net_wrap.net(), hostname, port,
            std::bind(&handshake_wrapper::post_connect,
                ph::_1, ph::_2, handle_connect));
    }
    void ready(channel_wrapper node, python::object handle_handshake)
    {
        hs_->ready(node.channel(),
            pyfunction<const std::error_code&>(handle_handshake));
    }
    void discover_external_ip(python::object handle_discover)
    {
        hs_->discover_external_ip(
            pyfunction<const std::error_code&,
                const bc::message::ip_address&>(handle_discover));
    }
    void fetch_network_address(python::object handle_fetch)
    {
        hs_->fetch_network_address(
            pyfunction<const std::error_code&,
                const bc::message::network_address&>(handle_fetch));
    }
    void set_port(uint16_t port, python::object handle_set)
    {
        hs_->set_port(port,
            pyfunction<const std::error_code&>(handle_set));
    }
    void set_user_agent(const std::string& user_agent,
        python::object handle_set)
    {
        hs_->set_user_agent(user_agent,
            pyfunction<const std::error_code&>(handle_set));
    }

    bc::handshake_ptr hs()
    {
        return hs_;
    }
private:
    static void post_connect(const std::error_code& ec,
        bc::channel_ptr node, python::object handle_connect)
    {
        ensure_gil eg;
        pyfunction<const std::error_code&,
            channel_wrapper> f(handle_connect);
        f(ec, channel_wrapper(node));
    }
    bc::handshake_ptr hs_;
};

class hosts_wrapper
{
public:
    hosts_wrapper(async_service_wrapper service)
    {
        hosts_ = std::make_shared<bc::hosts>(*service.s);
    }

    void load(const std::string& filename, python::object handle_load)
    {
        hosts_->load(filename, pyfunction<const std::error_code&>(handle_load));
    }
    void save(const std::string& filename, python::object handle_save)
    {
        hosts_->save(filename, pyfunction<const std::error_code&>(handle_save));
    }

    void store(const bc::message::network_address& address,
        python::object handle_store)
    {
        hosts_->store(address,
            pyfunction<const std::error_code&>(handle_store));
    }
    void remove(const bc::message::network_address& address,
        python::object handle_remove)
    {
        hosts_->store(address,
            pyfunction<const std::error_code&>(handle_remove));
    }

    void fetch_address(python::object handle_fetch)
    {
        hosts_->fetch_address(
            pyfunction<const std::error_code&,
                const bc::message::network_address&>(handle_fetch));
    }

    void fetch_count(python::object handle_fetch)
    {
        hosts_->fetch_count(
            pyfunction<const std::error_code&, size_t>(handle_fetch));
    }

    bc::hosts_ptr hsts()
    {
        return hosts_;
    }
private:
    bc::hosts_ptr hosts_;
};

class protocol_wrapper
{
public:
    protocol_wrapper(async_service_wrapper service,
        hosts_wrapper h, handshake_wrapper hs, network_wrapper n)
    {
        protocol_ = std::make_shared<bc::protocol>(*service.s,
            h.hsts(), hs.hs(), n.net());
    }

    void start(python::object handle_complete)
    {
        protocol_->start(
            pyfunction<const std::error_code&>(handle_complete));
    }
    void stop(python::object handle_complete)
    {
        protocol_->stop(
            pyfunction<const std::error_code&>(handle_complete));
    }

    void bootstrap(python::object handle_complete)
    {
        protocol_->bootstrap(
            pyfunction<const std::error_code&>(handle_complete));
    }
    void run()
    {
        protocol_->run();
    }

    void fetch_connection_count(python::object handle_fetch)
    {
        protocol_->fetch_connection_count(
            pyfunction<const std::error_code&, size_t>(handle_fetch));
    }
    void subscribe_channel(python::object handle_channel)
    {
        protocol_->subscribe_channel(
            std::bind(&protocol_wrapper::post_new_channel,
                ph::_1, handle_channel));
    }

    bc::protocol_ptr prot()
    {
        return protocol_;
    }
private:
    static void post_new_channel(bc::channel_ptr node,
        python::object handle_channel)
    {
        ensure_gil eg;
        pyfunction<channel_wrapper> f(handle_channel);
        f(channel_wrapper(node));
    }
    bc::protocol_ptr protocol_;
};

template <typename ListType>
std::string raw_list(const ListType& listobj)
{
    return std::string(listobj.begin(), listobj.end());
}
template <typename HashType>
void set_raw_hash(HashType& hashobj, const std::string& raw_repr)
{
    for (size_t i = 0; i < hashobj.size() && i < raw_repr.size(); ++i)
        hashobj[i] = raw_repr[i];
}
void set_raw_data_chunk(bc::data_chunk& d, const std::string& raw_repr)
{
    d.resize(raw_repr.size());
    std::copy(raw_repr.begin(), raw_repr.end(), d.begin());
}

template <typename ListType, typename ClassType>
ClassType& extend_vector(ClassType& pyclass)
{
    pyclass
        .def("__len__", &ListType::size)
        .def("clear", &ListType::clear)
        .def("append", &std_item<ListType>::add,
            python::with_custodian_and_ward<1, 2>())
        .def("__getitem__", &std_item<ListType>::get)
        .def("__setitem__", &std_item<ListType>::set,
            python::with_custodian_and_ward<1, 2>())
        .def("__delitem__", &std_item<ListType>::del)
    ;
    return pyclass;
}

template <typename HashType>
static bool hash_eq(const HashType& h, const char* other_repr)
{
    return bc::pretty_hex(h) == other_repr;
}
static bool hash_digest_nonzero(const bc::hash_digest& h)
{
    return h == bc::null_hash;
}
static bool short_hash_nonzero(const bc::short_hash& h)
{
    return h == bc::null_short_hash;
}

template <typename HashType, typename ClassType>
ClassType& extend_hash(ClassType& pyclass)
{
    pyclass
        .def("__repr__", bc::pretty_hex<HashType>)
        .def("__str__", bc::pretty_hex<HashType>)
        .def("__len__", &HashType::size)
        .def("__getitem__", &std_item<HashType>::get)
        .def("__setitem__", &std_item<HashType>::set)
        .def("__eq__", hash_eq<HashType>)
        .add_property("raw", raw_list<HashType>, set_raw_hash<HashType>)
    ;
    return pyclass;
}

class network_address_wrapper
{
public:
    static python::list get_ip(const bc::message::network_address& net)
    {
        python::list result;
        for (const uint8_t& v: net.ip)
            result.append(v);
        return result;
    }

    static void set_ip(bc::message::network_address& net, python::list passed)
    {
        for (size_t i = 0; i < net.ip.size() && i < (size_t)len(passed); ++i)
            net.ip[i] = python::extract<uint8_t>(passed[i]);
    }
};

enum class sighash_wrapper
{
    all = bc::sighash::all,
    none = bc::sighash::none,
    single = bc::sighash::single,
    anyone_can_pay = bc::sighash::anyone_can_pay
};

class script_wrapper
{
public:
    // boost python doesnt like the constref return type
    static bc::operation_stack operations(const bc::script& s)
    {
        return s.operations();
    }
    static bool run(bc::script& a, bc::script scrin,
        bc::message::transaction tx, uint32_t inidx)
    {
        return a.run(scrin, tx, inidx);
    }
};

class exporter_wrapper
{
public:
    exporter_wrapper(bc::exporter_ptr ex)
      : ex_(ex)
    {
    }

    bc::data_chunk save_header(const bc::message::header& pkt) const
    {
        return ex_->save(pkt);
    }
    bc::data_chunk save_version(const bc::message::version& pkt) const
    {
        return ex_->save(pkt);
    }
    bc::data_chunk save_verack(const bc::message::verack& pkt) const
    {
        return ex_->save(pkt);
    }
    bc::data_chunk save_address(const bc::message::address& pkt) const
    {
        return ex_->save(pkt);
    }
    bc::data_chunk save_get_address(const bc::message::get_address& pkt) const
    {
        return ex_->save(pkt);
    }
    bc::data_chunk save_inventory(const bc::message::inventory& pkt) const
    {
        return ex_->save(pkt);
    }
    bc::data_chunk save_get_data(const bc::message::get_data& pkt) const
    {
        return ex_->save(pkt);
    }
    bc::data_chunk save_get_blocks(const bc::message::get_blocks& pkt) const
    {
        return ex_->save(pkt);
    }
    bc::data_chunk save_transaction(const bc::message::transaction& pkt) const
    {
        return ex_->save(pkt);
    }
    bc::data_chunk save_block(const bc::message::block& pkt) const
    {
        return ex_->save(pkt);
    }
    bc::data_chunk save_ping(const bc::message::ping& pkt) const
    {
        return ex_->save(pkt);
    }

    bc::message::header load_header(const bc::data_chunk& stream) const
    {
        return ex_->load_header(stream);
    }
    bc::message::version load_version(const bc::data_chunk& stream) const
    {
        return ex_->load_version(stream);
    }
    bc::message::verack load_verack(const bc::data_chunk& stream) const
    {
        return ex_->load_verack(stream);
    }
    bc::message::address load_address(const bc::data_chunk& stream) const
    {
        return ex_->load_address(stream);
    }
    bc::message::get_address load_get_address(const bc::data_chunk& stream) const
    {
        return ex_->load_get_address(stream);
    }
    bc::message::inventory load_inventory(const bc::data_chunk& stream) const
    {
        return ex_->load_inventory(stream);
    }
    bc::message::get_data load_get_data(const bc::data_chunk& stream) const
    {
        return ex_->load_get_data(stream);
    }
    bc::message::get_blocks load_get_blocks(const bc::data_chunk& stream) const
    {
        return ex_->load_get_blocks(stream);
    }
    bc::message::transaction load_transaction(
        const bc::data_chunk& stream) const
    {
        return ex_->load_transaction(stream);
    }
    bc::message::block load_block(const bc::data_chunk& stream) const
    {
        return ex_->load_block(stream);
    }
    bc::message::ping load_ping(const bc::data_chunk& stream) const
    {
        return ex_->load_ping(stream);
    }

    bool verify_header(const bc::message::header& header_msg) const
    {
        return ex_->verify_header(header_msg);
    }
private:
    bc::exporter_ptr ex_;
};

exporter_wrapper create_satoshi_exporter()
{
    return exporter_wrapper(std::make_shared<bc::satoshi_exporter>());
}

class blockchain_wrapper
{
public:
    blockchain_wrapper(bc::blockchain_ptr chain)
      : chain_(chain)
    {
    }

    void store(const bc::message::block& blk, python::object handle_store)
    {
        chain_->store(blk,
            pyfunction<const std::error_code&, bc::block_info>(handle_store));
    }

    void fetch_block_header_by_depth(size_t depth, python::object handle_fetch)
    {
        chain_->fetch_block_header(depth,
            pyfunction<const std::error_code&,
                const bc::message::block&>(handle_fetch));
    }
    void fetch_block_header_by_hash(const bc::hash_digest& block_hash,
        python::object handle_fetch)
    {
        chain_->fetch_block_header(block_hash,
            pyfunction<const std::error_code&,
                const bc::message::block&>(handle_fetch));
    }
    void fetch_block_transaction_hashes_by_depth(size_t depth,
        python::object handle_fetch)
    {
        chain_->fetch_block_transaction_hashes(depth,
            pyfunction<const std::error_code&,
                const bc::message::inventory_list&>(handle_fetch));
    }
    void fetch_block_transaction_hashes_by_hash(
        const bc::hash_digest& block_hash, python::object handle_fetch)
    {
        chain_->fetch_block_transaction_hashes(block_hash,
            pyfunction<const std::error_code&,
                const bc::message::inventory_list&>(handle_fetch));
    }
    void fetch_block_depth(const bc::hash_digest& block_hash,
        python::object handle_fetch)
    {
        chain_->fetch_block_depth(block_hash,
            pyfunction<const std::error_code&, size_t>(handle_fetch));
    }
    void fetch_last_depth(python::object handle_fetch)
    {
        chain_->fetch_last_depth(
            pyfunction<const std::error_code&, size_t>(handle_fetch));
    }
    void fetch_block_locator(python::object handle_fetch)
    {
        chain_->fetch_block_locator(
            pyfunction<const std::error_code&,
                const bc::message::block_locator&>(handle_fetch));
    }
    void fetch_transaction(const bc::hash_digest& transaction_hash,
        python::object handle_fetch)
    {
        chain_->fetch_transaction(transaction_hash,
            pyfunction<const std::error_code&,
                const bc::message::transaction&>(handle_fetch));
    }
    void fetch_transaction_index(
        const bc::hash_digest& transaction_hash,
        python::object handle_fetch)
    {
        chain_->fetch_transaction_index(transaction_hash,
            pyfunction<const std::error_code&,
                size_t, size_t>(handle_fetch));
    }
    void fetch_spend(const bc::message::output_point& outpoint,
        python::object handle_fetch)
    {
        chain_->fetch_spend(outpoint,
            pyfunction<const std::error_code&,
                const bc::message::input_point&>(handle_fetch));
    }
    void fetch_outputs(const bc::short_hash& pubkey_hash,
        python::object handle_fetch)
    {
        chain_->fetch_outputs(pubkey_hash,
            pyfunction<const std::error_code&,
                const bc::message::output_point_list&>(handle_fetch));
    }

    void subscribe_reorganize(python::object handle_reorganize)
    {
        chain_->subscribe_reorganize(
            std::bind(&blockchain_wrapper::call_handle_reorganize,
                ph::_1, ph::_2, ph::_3, ph::_4, handle_reorganize));
    }

    bc::blockchain_ptr chain()
    {
        return chain_;
    }
private:
    static void call_handle_reorganize(const std::error_code& ec,
        size_t fork_point,
        const bc::blockchain::block_list& arrivals,
        const bc::blockchain::block_list& replaced,
        python::object handle_reorganize)
    {
        python::list py_arrivals, py_replaced;
        for (auto blk: arrivals)
            py_arrivals.append(*blk);
        for (auto blk: replaced)
            py_replaced.append(*blk);
        ensure_gil eg;
        pyfunction<const std::error_code&, size_t, python::list, python::list>
            f(handle_reorganize);
        f(ec, fork_point, py_arrivals, py_replaced);
    }

    bc::blockchain_ptr chain_;
};

blockchain_wrapper create_bdb_blockchain(async_service_wrapper service,
    const std::string& prefix)
{
    return blockchain_wrapper(
        bc::bdb_blockchain::create(*service.s, prefix));
}
bool setup_bdb_blockchain(const std::string& prefix)
{
    return bc::bdb_blockchain::setup(prefix);
}

std::string pretty_input_point(const bc::message::input_point& inpoint)
{
    return bc::pretty_hex(inpoint.hash) + ":" +
        boost::lexical_cast<std::string>(inpoint.index);
}

class poller_wrapper
{
public:
    poller_wrapper(blockchain_wrapper chain)
    {
        poll_ = std::make_shared<bc::poller>(chain.chain());
    }
    void query(channel_wrapper node)
    {
        poll_->query(node.channel());
    }

    bc::poller_ptr p()
    {
        return poll_;
    }
private:
    bc::poller_ptr poll_;
};

void disable_logging()
{
    bc::log_debug().alias(bc::log_level::debug, bc::log_level::null);
    bc::log_debug().alias(bc::log_level::info, bc::log_level::null);
}

class transaction_pool_wrapper
{
public:
    transaction_pool_wrapper(async_service_wrapper service,
        blockchain_wrapper b)
    {
        pool_ = bc::transaction_pool::create(*service.s, b.chain());
    }

    bc::transaction_pool_ptr p()
    {
        return pool_;
    }

    void store(const bc::message::transaction& tx,
        python::object handle_confirm, python::object handle_store)
    {
        pool_->store(tx,
            pyfunction<const std::error_code&>(handle_confirm),
            pyfunction<const std::error_code&>(handle_store));
    }

    void exists(const bc::hash_digest& tx_hash,
        python::object handle_exists)
    {
        pool_->exists(tx_hash,
            pyfunction<bool>(handle_exists));
    }
private:
    bc::transaction_pool_ptr pool_;
};

class session_wrapper
{
public:
    session_wrapper(
        hosts_wrapper hsts,
        handshake_wrapper h,
        network_wrapper n,
        protocol_wrapper pp,
        blockchain_wrapper chain,
        poller_wrapper pl,
        transaction_pool_wrapper tp)
    {
        bc::session_params p;
        p.hosts_ = hsts.hsts();
        p.handshake_ = h.hs();
        p.network_ = n.net();
        p.protocol_ = pp.prot();
        p.poller_ = pl.p();
        p.blockchain_ = chain.chain();
        p.transaction_pool_ = tp.p();
        session_ = std::make_shared<bc::session>(p);
    }

    void start(python::object handle_complete)
    {
        session_->start(
            pyfunction<const std::error_code&>(handle_complete));
    }
    void stop(python::object handle_complete)
    {
        session_->stop(
            pyfunction<const std::error_code&>(handle_complete));
    }
private:
    bc::session_ptr session_;
};

BOOST_PYTHON_MODULE(_bitcoin)
{
    PyEval_InitThreads();
    //PyEval_ReleaseLock();

    using namespace boost::python;
    def("disable_logging", disable_logging);
    // types.hpp
    def("bytes_from_pretty", bc::bytes_from_pretty);
    auto data_chunk_class =
        class_<bc::data_chunk>("_data_chunk")
            .def("__repr__", bc::pretty_hex<bc::data_chunk>)
            .def("__str__", bc::pretty_hex<bc::data_chunk>)
            .add_property("raw", raw_list<bc::data_chunk>, set_raw_data_chunk)
        ;
    extend_vector<bc::data_chunk>(data_chunk_class);
    def("hash_digest_from_pretty", bc::hash_from_pretty<bc::hash_digest>);
    auto hash_digest_class =
        class_<bc::hash_digest>("_hash_digest")
            .def("__nonzero__", hash_digest_nonzero)
        ;
    extend_hash<bc::hash_digest>(hash_digest_class);
    def("short_hash_from_pretty", bc::hash_from_pretty<bc::short_hash>);
    auto short_hash_class =
        class_<bc::short_hash>("short_hash_wrapper")
            .def("__nonzero__", short_hash_nonzero)
        ;
    extend_hash<bc::short_hash>(short_hash_class);
    class_<atomic_counter_wrapper>("atomic_counter", init<size_t>())
        .def("increment", &atomic_counter_wrapper::increment)
        .def("count", &atomic_counter_wrapper::count)
    ;
    // address.hpp
    def("public_key_to_address", bc::public_key_to_address);
    def("address_to_short_hash", bc::address_to_short_hash);
    // block.hpp
    enum_<bc::block_status>("block_status")
        .value("orphan", bc::block_status::orphan)
        .value("confirmed", bc::block_status::confirmed)
        .value("rejected", bc::block_status::rejected)
    ;
    class_<bc::block_info>("block_info")
        .def_readwrite("status", &bc::block_info::status)
        .def_readwrite("depth", &bc::block_info::depth)
    ;
    def("block_value", bc::block_value);
    def("block_work", bc::block_work);
    def("hash_block_header", bc::hash_block_header);
    auto indices_list_class =
        class_<bc::indices_list>("indices_list")
        ;
    extend_vector<bc::indices_list>(indices_list_class);
    def("block_locator_indices", bc::block_locator_indices);
    def("genesis_block", bc::genesis_block);
    // constants.hpp
    scope().attr("block_reward") = bc::block_reward;
    scope().attr("reward_interval") = bc::reward_interval;
    scope().attr("coinbase_maturity") = bc::coinbase_maturity;
    scope().attr("magic_value") = bc::magic_value;
    def("coin_price", bc::coin_price);
    scope().attr("max_money") = bc::max_money();
    scope().attr("null_hash") = bc::null_hash;
    scope().attr("null_short_hash") = bc::null_short_hash;
    scope().attr("max_bits") = bc::max_bits;
    def("max_target", bc::max_target);
    scope().attr("target_timespan") = bc::target_timespan;
    scope().attr("target_spacing") = bc::target_spacing;
    scope().attr("readjustment_interval") = bc::readjustment_interval;
    // transaction.hpp
    bc::hash_digest (*hash_transaction)(
        const bc::message::transaction& transaction) = bc::hash_transaction;
    def("hash_transaction", hash_transaction);
    def("generate_merkle_root", bc::generate_merkle_root);
    def("previous_output_is_null", bc::previous_output_is_null);
    def("is_coinbase", bc::is_coinbase);
    def("total_output_value", bc::total_output_value);
    // util/base58.hpp
    def("encode_base58", bc::encode_base58);
    def("decode_base58", bc::decode_base58);
    // util/ripemd.hpp
    def("generate_ripemd_hash", bc::generate_ripemd_hash);
    // util/sha256.hpp
    def("generate_sha256_hash", bc::generate_sha256_hash);
    def("generate_sha256_checksum", bc::generate_sha256_checksum);
    // messages.hpp
    auto block_locator_class =
        class_<bc::message::block_locator>("block_locator")
        ;
    extend_vector<bc::message::block_locator>(block_locator_class);
    class_<bc::message::network_address>("network_address")
        .def_readwrite("timestamp", &bc::message::network_address::timestamp)
        .def_readwrite("service", &bc::message::network_address::services)
        .add_property("ip",
            &network_address_wrapper::get_ip,
            &network_address_wrapper::set_ip)
        .def_readwrite("port", &bc::message::network_address::port)
    ;
    enum_<bc::message::inventory_type>("inventory_type")
        .value("error", bc::message::inventory_type::error)
        .value("transaction", bc::message::inventory_type::transaction)
        .value("block", bc::message::inventory_type::block)
        .value("none", bc::message::inventory_type::none)
    ;
    class_<bc::message::inventory_vector>("inventory_vector")
        .def_readwrite("type", &bc::message::inventory_vector::type)
        .def_readwrite("hash", &bc::message::inventory_vector::hash)
    ;
    auto inventory_list_class =
        class_<bc::message::inventory_list>("inventory_list")
    ;
    extend_vector<bc::message::inventory_list>(inventory_list_class);
    class_<bc::message::header>("header")
        .def_readwrite("magic", &bc::message::header::magic)
        .def_readwrite("command", &bc::message::header::command)
        .def_readwrite("payload_length", &bc::message::header::payload_length)
        .def_readwrite("checksum", &bc::message::header::checksum)
    ;
    class_<bc::message::version>("version")
        .def_readwrite("version", &bc::message::version::version)
        .def_readwrite("services", &bc::message::version::services)
        .def_readwrite("timestamp", &bc::message::version::timestamp)
        .def_readwrite("address_me", &bc::message::version::address_me)
        .def_readwrite("address_you", &bc::message::version::address_you)
        .def_readwrite("nonce", &bc::message::version::nonce)
        .def_readwrite("user_agent", &bc::message::version::user_agent)
        .def_readwrite("start_depth", &bc::message::version::start_depth)
    ;
    class_<bc::message::verack>("verack")
    ;
    class_<bc::message::get_address>("get_address")
    ;
    class_<bc::message::get_blocks>("get_blocks")
        .def_readwrite("start_hashes", &bc::message::get_blocks::start_hashes)
        .def_readwrite("hash_stop", &bc::message::get_blocks::hash_stop)
    ;
    class_<bc::message::input_point>("input_point")
        .def_readwrite("hash", &bc::message::input_point::hash)
        .def_readwrite("index", &bc::message::input_point::index)
        .def("__repr__", pretty_input_point)
    ;
    // output_point defined in python wrapper
    auto output_point_list_class =
        class_<bc::message::output_point_list>("output_point_list")
        ;
    extend_vector<bc::message::output_point_list>(output_point_list_class);
    class_<bc::message::transaction_input>("transaction_input")
        .def_readwrite("previous_output",
            &bc::message::transaction_input::previous_output)
        .def_readwrite("input_script",
            &bc::message::transaction_input::input_script)
        .def_readwrite("sequence", &bc::message::transaction_input::sequence)
    ;
    class_<bc::message::transaction_output>("transaction_output")
        .def_readwrite("value", &bc::message::transaction_output::value)
        .def_readwrite("output_script",
            &bc::message::transaction_output::output_script)
    ;
    auto transaction_input_list_class =
        class_<bc::message::transaction_input_list>("transaction_input_list")
        ;
    extend_vector<bc::message::transaction_input_list>(
        transaction_input_list_class);
    auto transaction_output_list_class =
        class_<bc::message::transaction_output_list>("transaction_output_list")
        ;
    extend_vector<bc::message::transaction_output_list>(
        transaction_output_list_class);
    class_<bc::message::transaction>("transaction")
        .def_readwrite("version", &bc::message::transaction::version)
        .def_readwrite("locktime", &bc::message::transaction::locktime)
        .def_readwrite("inputs", &bc::message::transaction::inputs)
        .def_readwrite("outputs", &bc::message::transaction::outputs)
        .def("__repr__", bc::pretty);
    ;
    auto transaction_list_class =
        class_<bc::message::transaction_list>("transaction_list")
        ;
    extend_vector<bc::message::transaction_list>(transaction_list_class);
    class_<bc::message::block>("block")
        .def_readwrite("version", &bc::message::block::version)
        .def_readwrite("previous_block_hash",
            &bc::message::block::previous_block_hash)
        .def_readwrite("merkle", &bc::message::block::merkle)
        .def_readwrite("timestamp", &bc::message::block::timestamp)
        .def_readwrite("bits", &bc::message::block::bits)
        .def_readwrite("nonce", &bc::message::block::nonce)
        .def_readwrite("transactions", &bc::message::block::transactions)
    ;
    auto network_address_list_class =
        class_<bc::message::network_address_list>("network_address_list")
        ;
    extend_vector<bc::message::network_address_list>(
        network_address_list_class);
    class_<bc::message::address>("address")
        .def_readwrite("addresses", &bc::message::address::addresses)
    ;
    class_<bc::message::get_data>("get_data")
        .def_readwrite("inventories", &bc::message::get_data::inventories)
    ;
    class_<bc::message::inventory>("inventory")
        .def_readwrite("inventories", &bc::message::inventory::inventories)
    ;
    class_<bc::message::ping>("ping")
    ;
    // script.hpp
    enum_<bc::opcode>("opcode")
        .value("raw_data", bc::opcode::raw_data)
        .value("special", bc::opcode::special)
        .value("pushdata1", bc::opcode::pushdata1)
        .value("pushdata2", bc::opcode::pushdata2)
        .value("pushdata4", bc::opcode::pushdata4)
        .value("nop", bc::opcode::nop)
        .value("drop", bc::opcode::drop)
        .value("dup", bc::opcode::dup)
        .value("sha256", bc::opcode::sha256)
        .value("hash160", bc::opcode::hash160)
        .value("equal", bc::opcode::equal)
        .value("equalverify", bc::opcode::equalverify)
        .value("checksig", bc::opcode::checksig)
        .value("codeseparator", bc::opcode::codeseparator)
        .value("bad_operation", bc::opcode::bad_operation)
    ;
    class_<bc::operation>("operation")
        .def_readwrite("code", &bc::operation::code)
        .def_readwrite("data", &bc::operation::data)
    ;
    enum_<sighash_wrapper>("sighash")
        .value("all", sighash_wrapper::all)
        .value("none", sighash_wrapper::none)
        .value("single", sighash_wrapper::single)
        .value("anyone_can_pay", sighash_wrapper::anyone_can_pay)
    ;
    auto operation_stack_class =
        class_<bc::operation_stack>("operation_stack")
        ;
    extend_vector<bc::operation_stack>(operation_stack_class);
    enum_<bc::payment_type>("payment_type")
        .value("pubkey", bc::payment_type::pubkey)
        .value("pubkey_hash", bc::payment_type::pubkey_hash)
        .value("script_hash", bc::payment_type::script_hash)
        .value("multisig", bc::payment_type::multisig)
        .value("non_standard", bc::payment_type::non_standard)
    ;
    class_<bc::script>("script")
        .def("join", &bc::script::join)
        .def("push_operation", &bc::script::push_operation)
        .def("run", &script_wrapper::run)
        .def("__repr__", &bc::script::pretty)
        .def("type", &bc::script::type)
        .def("operations", &script_wrapper::operations)
        .def("generate_signature_hash", &bc::script::generate_signature_hash)
        .staticmethod("generate_signature_hash")
    ;
    def("opcode_to_string", bc::opcode_to_string);
    def("string_to_opcode", bc::string_to_opcode);
    def("coinbase_script", bc::coinbase_script);
    def("parse_script", bc::parse_script);
    def("save_script", bc::save_script);
    // error.hpp
    enum_<libbitcoin::error::error_code_t>("error")
        .value("missing_object", bc::error::missing_object)
        .value("object_already_exists", bc::error::object_already_exists)
        .value("unspent_output", bc::error::unspent_output)
        .value("bad_transaction", bc::error::bad_transaction)
        .value("resolve_failed", bc::error::resolve_failed)
        .value("network_unreachable", bc::error::network_unreachable)
        .value("address_in_use", bc::error::address_in_use)
        .value("listen_failed", bc::error::listen_failed)
        .value("accept_failed", bc::error::accept_failed)
        .value("bad_stream", bc::error::bad_stream)
        .value("channel_stopped", bc::error::channel_stopped)
        .value("channel_timeout", bc::error::channel_timeout)
    ;
    class_<std::error_code>("error_code", init<bc::error::error_code_t>())
        .def("__str__", &std::error_code::message)
        .def("__repr__", &std::error_code::message)
        .def("__nonzero__", &error_code_wrapper::nonzero)
        .def("__eq__", &error_code_wrapper::eq)
    ;
    // network stuff
    class_<acceptor_wrapper>("acceptor", no_init)
        .def("accept", &acceptor_wrapper::accept)
    ;
    class_<channel_wrapper>("channel", no_init)
        .def("stop", &channel_wrapper::stop)
        .def("stopped", &channel_wrapper::stopped)
        .def("send_version", &channel_wrapper::send<bc::message::version>)
        .def("send_verack", &channel_wrapper::send<bc::message::verack>)
        .def("send_address", &channel_wrapper::send<bc::message::address>)
        .def("send_get_address",
            &channel_wrapper::send<bc::message::get_address>)
        .def("send_inventory", &channel_wrapper::send<bc::message::inventory>)
        .def("send_get_data", &channel_wrapper::send<bc::message::get_data>)
        .def("send_get_blocks",
            &channel_wrapper::send<bc::message::get_blocks>)
        .def("send_transaction",
            &channel_wrapper::send<bc::message::transaction>)
        .def("send_block", &channel_wrapper::send<bc::message::block>)
        .def("send_raw", &channel_wrapper::send_raw)

        .def("subscribe_version", &channel_wrapper::subscribe_version)
        .def("subscribe_verack", &channel_wrapper::subscribe_verack)
        .def("subscribe_address", &channel_wrapper::subscribe_address)
        .def("subscribe_get_address", &channel_wrapper::subscribe_get_address)
        .def("subscribe_inventory", &channel_wrapper::subscribe_inventory)
        .def("subscribe_get_data", &channel_wrapper::subscribe_get_data)
        .def("subscribe_get_blocks", &channel_wrapper::subscribe_get_blocks)
        .def("subscribe_transaction", &channel_wrapper::subscribe_transaction)
        .def("subscribe_block", &channel_wrapper::subscribe_block)
        .def("subscribe_raw", &channel_wrapper::subscribe_raw)
    ;
    class_<network_wrapper>("network", init<async_service_wrapper>())
        .def("listen", &network_wrapper::listen)
        .def("connect", &network_wrapper::connect)
    ;
    class_<handshake_wrapper>("handshake", init<async_service_wrapper>())
        .def("start", &handshake_wrapper::start)
        .def("connect", &handshake_wrapper::connect)
        .def("ready", &handshake_wrapper::ready)
        .def("discover_external_ip", &handshake_wrapper::discover_external_ip)
        .def("fetch_network_address", &handshake_wrapper::fetch_network_address)
        .def("set_port", &handshake_wrapper::set_port)
        .def("set_user_agent", &handshake_wrapper::set_user_agent)
    ;
    // hosts
    class_<hosts_wrapper>("hosts", init<async_service_wrapper>())
        .def("load", &hosts_wrapper::load)
        .def("save", &hosts_wrapper::save)
        .def("store", &hosts_wrapper::store)
        .def("remove", &hosts_wrapper::remove)
        .def("fetch_address", &hosts_wrapper::fetch_address)
        .def("fetch_count", &hosts_wrapper::fetch_count)
    ;
    // protocol
    class_<protocol_wrapper>("protocol",
        init<async_service_wrapper, hosts_wrapper,
            handshake_wrapper, network_wrapper>())
        .def("start", &protocol_wrapper::start)
        .def("stop", &protocol_wrapper::stop)
        .def("bootstrap", &protocol_wrapper::bootstrap)
        .def("run", &protocol_wrapper::run)
        .def("fetch_connection_count",
            &protocol_wrapper::fetch_connection_count)
        .def("subscribe_channel", &protocol_wrapper::subscribe_channel)
    ;
    // exporter.hpp
    def("satoshi_exporter", create_satoshi_exporter);
    class_<exporter_wrapper>("exporter", no_init)
        .def("save_header", &exporter_wrapper::save_header)
        .def("save_version", &exporter_wrapper::save_version)
        .def("save_verack", &exporter_wrapper::save_verack)
        .def("save_address", &exporter_wrapper::save_address)
        .def("save_get_address", &exporter_wrapper::save_get_address)
        .def("save_inventory", &exporter_wrapper::save_inventory)
        .def("save_get_data", &exporter_wrapper::save_get_data)
        .def("save_get_blocks", &exporter_wrapper::save_get_blocks)
        .def("save_transaction", &exporter_wrapper::save_transaction)
        .def("save_block", &exporter_wrapper::save_block)
        .def("save_ping", &exporter_wrapper::save_ping)
        .def("load_header", &exporter_wrapper::load_header)
        .def("load_version", &exporter_wrapper::load_version)
        .def("load_verack", &exporter_wrapper::load_verack)
        .def("load_address", &exporter_wrapper::load_address)
        .def("load_get_address", &exporter_wrapper::load_get_address)
        .def("load_inventory", &exporter_wrapper::load_inventory)
        .def("load_get_data", &exporter_wrapper::load_get_data)
        .def("load_get_blocks", &exporter_wrapper::load_get_blocks)
        .def("load_transaction", &exporter_wrapper::load_transaction)
        .def("load_block", &exporter_wrapper::load_block)
        .def("load_ping", &exporter_wrapper::load_ping)
        .def("verify_header", &exporter_wrapper::verify_header)
    ;
    // utility/elliptic_curve_key.hpp
    class_<bc::elliptic_curve_key>("elliptic_curve_key")
        .def("set_public_key", &bc::elliptic_curve_key::set_public_key)
        .def("public_key", &bc::elliptic_curve_key::public_key)
        .def("verify", &bc::elliptic_curve_key::verify)
        .def("new_key_pair", &bc::elliptic_curve_key::new_key_pair)
        .def("set_private_key", &bc::elliptic_curve_key::set_private_key)
        .def("private_key", &bc::elliptic_curve_key::private_key)
        .def("sign", &bc::elliptic_curve_key::sign)
    ;
    // blockchain
    def("bdb_blockchain", create_bdb_blockchain);
    def("setup_bdb_blockchain", setup_bdb_blockchain);
    class_<blockchain_wrapper>("blockchain", no_init)
        .def("store", &blockchain_wrapper::store)
        .def("fetch_block_header_by_depth",
            &blockchain_wrapper::fetch_block_header_by_depth)
        .def("fetch_block_header_by_hash",
            &blockchain_wrapper::fetch_block_header_by_hash)
        .def("fetch_block_transaction_hashes_by_depth",
            &blockchain_wrapper::fetch_block_transaction_hashes_by_depth)
        .def("fetch_block_transaction_hashes_by_hash",
            &blockchain_wrapper::fetch_block_transaction_hashes_by_hash)
        .def("fetch_block_depth", &blockchain_wrapper::fetch_block_depth)
        .def("fetch_last_depth", &blockchain_wrapper::fetch_last_depth)
        .def("fetch_block_locator", &blockchain_wrapper::fetch_block_locator)
        .def("fetch_transaction", &blockchain_wrapper::fetch_transaction)
        .def("fetch_transaction_index",
            &blockchain_wrapper::fetch_transaction_index)
        .def("fetch_spend", &blockchain_wrapper::fetch_spend)
        .def("fetch_outputs", &blockchain_wrapper::fetch_outputs)
        .def("subscribe_reorganize",
            &blockchain_wrapper::subscribe_reorganize)
    ;
    // async_service
    class_<async_service_wrapper>("async_service")
        .def(init<size_t>())
        .def("spawn", &async_service_wrapper::spawn)
        .def("shutdown", &async_service_wrapper::shutdown)
    ;
    // poller
    class_<poller_wrapper>("poller", init<blockchain_wrapper>())
        .def("query", &poller_wrapper::query)
    ;
    // transaction_pool
    class_<transaction_pool_wrapper>("transaction_pool",
            init<async_service_wrapper, blockchain_wrapper>())
        .def("store", &transaction_pool_wrapper::store)
        .def("exists", &transaction_pool_wrapper::exists)
    ;
    // session
    class_<session_wrapper>("session", init<
        hosts_wrapper,
        handshake_wrapper,
        network_wrapper,
        protocol_wrapper,
        blockchain_wrapper,
        poller_wrapper,
        transaction_pool_wrapper>())
        .def("start", &session_wrapper::start)
        .def("stop", &session_wrapper::stop)
    ;
}

