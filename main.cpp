#include <boost/python.hpp>
namespace python = boost::python;

#include <bitcoin/bitcoin.hpp>
namespace ph = std::placeholders;

void initialize_python()
{
    PyEval_InitThreads();
    PyEval_ReleaseLock();
}

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
        callable_(std::forward<Args>(params)...);
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
    static bool eq(const std::error_code& eca, libbitcoin::error err)
    {
        return eca == err;
    }
};

class acceptor_wrapper
{
public:
    acceptor_wrapper(bc::acceptor_ptr accept)
      : accept_(accept)
    {
    }
private:
    bc::acceptor_ptr accept_;
};

class channel_wrapper
{
public:
    channel_wrapper(bc::channel_ptr node)
      : node_(node)
    {
    }

    template <typename Message>
    void send(const Message& packet, python::object handle_send)
    {
        node_->send(packet, pyfunction<const std::error_code&>(handle_send));
    }
private:
    bc::channel_ptr node_;
};

class network_wrapper
{
public:
    network_wrapper()
    {
        net_ = std::make_shared<bc::network>();
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
private:
    static void post_listen(const std::error_code& ec,
        bc::acceptor_ptr accept, python::object handle_listen)
    {
        ensure_gil eg;
        handle_listen(ec, acceptor_wrapper(accept));
    }
    static void post_connect(const std::error_code& ec,
        bc::channel_ptr node, python::object handle_connect)
    {
        ensure_gil eg;
        handle_connect(ec, channel_wrapper(node));
    }
    bc::network_ptr net_;
};

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

BOOST_PYTHON_MODULE(_bitcoin)
{
    using namespace boost::python;
    def("initialize_python", initialize_python);
    // types.hpp
    def("bytes_from_pretty", bc::bytes_from_pretty);
    auto data_chunk_class =
        class_<bc::data_chunk>("_data_chunk")
            .def("__repr__", bc::pretty_hex<bc::data_chunk>)
            .def("__str__", bc::pretty_hex<bc::data_chunk>)
        ;
    extend_vector<bc::data_chunk>(data_chunk_class);
    def("hash_from_pretty", bc::hash_from_pretty);
    auto hash_digest_class =
        class_<bc::hash_digest>("_hash_digest")
            .def("__nonzero__", hash_digest_nonzero)
        ;
    extend_hash<bc::hash_digest>(hash_digest_class);
    auto short_hash_class =
        class_<bc::short_hash>("short_hash_wrapper")
            .def("__nonzero__", short_hash_nonzero)
        ;
    extend_hash<bc::short_hash>(short_hash_class);
    // address.hpp
    def("public_key_to_address", bc::public_key_to_address);
    def("address_to_short_hash", bc::address_to_short_hash);
    // block.hpp
    def("block_value", bc::block_value);
    def("hash_block_header", bc::hash_block_header);
    def("block_locator_indices", bc::block_locator_indices);
    def("genesis_block", bc::genesis_block);
    // constants.hpp
    // not sure how to export constants in boost::python
    def("coin_price", bc::coin_price);
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
        .def_readwrite("sub_version_num", &bc::message::version::user_agent)
        .def_readwrite("start_height", &bc::message::version::start_height)
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
    ;
    // output_point defined in python wrapper
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
    enum_<libbitcoin::error>("error")
        .value("missing_object", bc::error::missing_object)
        .value("object_already_exists", bc::error::object_already_exists)
        .value("unspent_output", bc::error::unspent_output)
        .value("bad_transaction", bc::error::bad_transaction)
        .value("resolve_failed", bc::error::resolve_failed)
        .value("network_unreachable", bc::error::network_unreachable)
        .value("accept_failed", bc::error::accept_failed)
        .value("bad_stream", bc::error::bad_stream)
        .value("channel_stopped", bc::error::channel_stopped)
    ;
    class_<std::error_code>("error_code", init<libbitcoin::error>())
        .def("__str__", &std::error_code::message)
        .def("__reor__", &std::error_code::message)
        .def("__nonzero__", &error_code_wrapper::nonzero)
        .def("__eq__", &error_code_wrapper::eq)
    ;
    // network stuff
    class_<acceptor_wrapper>("acceptor", no_init)
    ;
    class_<channel_wrapper>("channel", no_init)
        //.def("send_version", &channel_wrapper::send<bc::version>)
    ;
    class_<network_wrapper>("network")
        .def("listen", &network_wrapper::listen)
        .def("connect", &network_wrapper::connect)
    ;
}

