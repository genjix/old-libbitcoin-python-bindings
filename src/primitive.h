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

