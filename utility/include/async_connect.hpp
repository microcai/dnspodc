//
// async_connect.hpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2019 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <boost/asio/dispatch.hpp>
#include <boost/asio/connect.hpp>

#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include <atomic>
#include <utility>
#include <memory>
#include <vector>
#include <type_traits>


namespace asio_util {

	namespace detail {

		template <typename Stream>
		struct connect_params_detaila
		{
			std::atomic_int flag_;
			std::atomic_int num_;
			std::vector<boost::local_shared_ptr<Stream>> socket_;
		};

		template <typename Handler, typename ResultType>
		void do_result(Handler&& handler, const boost::system::error_code& error, ResultType&& result)
		{
			handler(error, result);
		}

		struct initiate_do_connect
		{
			template <typename Stream, typename Handler, typename Iterator, typename ResultType = void>
			void do_async_connect(Handler&& handler, Stream& stream, Iterator begin, Iterator end)
			{
				auto params = boost::make_local_shared<connect_params_detaila<Stream>>();

				params->flag_ = false;
				params->num_ = std::distance(begin, end);

				for (; begin != end; begin++)
				{
					auto sock = boost::make_local_shared<Stream>(stream.get_executor());
					params->socket_.emplace_back(sock);

					sock->async_connect(*begin, [&stream, params, begin, sock, handler]
					(const boost::system::error_code& error) mutable
					{
						if (!error)
						{
							if (params->flag_)
								return;

							params->flag_ = true;

							stream = std::move(*sock);
						}

						params->num_--;
						bool is_last = params->num_ == 0;

						if (error)
						{
							if (params->flag_ || !is_last)
								return;
						}

						auto& sockets = params->socket_;
						for (auto& s : sockets)
						{
							if (!s)
								continue;
							boost::system::error_code ignore_ec;
							s->cancel(ignore_ec);
						}

						boost::asio::detail::non_const_lvalue<Handler> handler2(handler);
						auto h = std::move(handler2.value);

						auto executor = boost::asio::get_associated_executor(h, stream.get_executor());

						boost::asio::dispatch(executor, [error, h, begin]() mutable
						{
							if constexpr (std::is_same<ResultType, typename Stream::endpoint_type>::value)
								do_result(h, error, *begin);
							if constexpr (!std::is_same<ResultType, typename Stream::endpoint_type>::value)
								do_result(h, error, begin);
						});
					});
				}
			}

			template <typename Stream, typename Iterator, typename Handler>
			void operator()(Handler&& handler, Stream& stream, Iterator begin, Iterator end)
			{
				do_async_connect(std::forward<Handler>(handler), stream, begin, end);
			}

			template <typename Stream, typename EndpointSequence, typename Handler>
			void operator()(Handler&& handler, Stream& stream, const EndpointSequence& endpoints)
			{
				auto begin = endpoints.begin();
				auto end = endpoints.end();
				using Iterator = decltype(begin);

				do_async_connect<Stream, Handler, Iterator, typename Stream::endpoint_type>(std::forward<Handler>(handler), stream, begin, end);
			}
		};
	}

	template <typename Stream,
	typename Iterator, typename IteratorConnectHandler>
	BOOST_ASIO_INITFN_RESULT_TYPE(IteratorConnectHandler,
		void(boost::system::error_code, Iterator))
	async_connect(Stream& stream, Iterator begin,
		BOOST_ASIO_MOVE_ARG(IteratorConnectHandler) handler,
		typename boost::asio::enable_if<!boost::asio::is_endpoint_sequence<Iterator>::value>::type* = 0)
	{
		return boost::asio::async_initiate<IteratorConnectHandler,
			void(boost::system::error_code, Iterator)>
			(detail::initiate_do_connect{}, handler, stream, begin, Iterator());
	}

	template <typename Stream,
		typename Iterator, typename IteratorConnectHandler>
		inline BOOST_ASIO_INITFN_RESULT_TYPE(IteratorConnectHandler,
			void(boost::system::error_code, Iterator))
		async_connect(Stream& stream, Iterator begin, Iterator end,
			BOOST_ASIO_MOVE_ARG(IteratorConnectHandler) handler)
	{
		return boost::asio::async_initiate<IteratorConnectHandler,
			void(boost::system::error_code, Iterator)>
			(detail::initiate_do_connect{}, handler, stream, begin, end);
	}

	template <typename Stream,
		typename EndpointSequence, typename IteratorConnectHandler>
		inline BOOST_ASIO_INITFN_RESULT_TYPE(IteratorConnectHandler,
			void(boost::system::error_code, typename Stream::endpoint_type))
		async_connect(Stream& stream, const EndpointSequence& endpoints,
			BOOST_ASIO_MOVE_ARG(IteratorConnectHandler) handler, 
			typename boost::asio::enable_if<boost::asio::is_endpoint_sequence<EndpointSequence>::value>::type* = 0)
	{
		return boost::asio::async_initiate<IteratorConnectHandler,
			void(boost::system::error_code, typename Stream::endpoint_type)>
			(detail::initiate_do_connect{}, handler, stream, endpoints);
	}
}
